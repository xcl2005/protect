#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <initguid.h>
#include <fwpmu.h>
#include <iphlpapi.h>
#include <userenv.h>

#include <algorithm>
#include <array>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ws2_32.lib")

namespace {
constexpr GUID ProviderKey{0xe806b976, 0xc249, 0x4601, {0xa3, 0x27, 0x5e, 0x3a, 0xcb, 0xd1, 0x33, 0x16}};
constexpr GUID SublayerKey{0x121fa623, 0xb2b6, 0x4cc4, {0x97, 0xb5, 0x4b, 0xa0, 0xb8, 0x91, 0x8c, 0x6b}};
wchar_t GuardName[] = L"Claude PopCat Outbound Guard";
wchar_t FilteringService[] = L"BFE";
constexpr wchar_t PackageFamily[] = L"Claude_pzs8sxrjxfjjc";
const std::array<GUID, 2> ConnectLayers{FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6};

void Check(DWORD result, const char* operation) {
    if (result == ERROR_SUCCESS) return;
    std::wcerr << operation << L" failed (0x" << std::hex << result << L").\n";
    throw std::runtime_error(operation);
}

struct Engine {
    HANDLE handle = nullptr;
    explicit Engine(bool dynamic = false) {
        FWPM_SESSION0 session{};
        if (dynamic) session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        Check(FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &handle), "Open WFP");
    }
    ~Engine() { FwpmEngineClose0(handle); }
    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;
};

struct Transaction {
    HANDLE engine;
    bool committed = false;
    explicit Transaction(HANDLE handle) : engine(handle) { Check(FwpmTransactionBegin0(engine, 0), "Begin WFP transaction"); }
    ~Transaction() { if (!committed) FwpmTransactionAbort0(engine); }
    void Commit() {
        Check(FwpmTransactionCommit0(engine), "Commit WFP transaction");
        committed = true;
    }
};

struct OutputLog {
    std::wofstream file;
    std::wstreambuf* stdoutBuffer = nullptr;
    std::wstreambuf* stderrBuffer = nullptr;
    void Open(const wchar_t* path) {
        file.open(path, std::ios::app);
        if (!file) throw std::runtime_error("Could not open the requested log.");
        stdoutBuffer = std::wcout.rdbuf(file.rdbuf());
        stderrBuffer = std::wcerr.rdbuf(file.rdbuf());
    }
    ~OutputLog() {
        if (stdoutBuffer) std::wcout.rdbuf(stdoutBuffer);
        if (stderrBuffer) std::wcerr.rdbuf(stderrBuffer);
    }
};

struct Identity {
    FWPM_FILTER_CONDITION0 condition{};
    FWP_BYTE_BLOB* appId = nullptr;
    PSID packageSid = nullptr;

    explicit Identity(const wchar_t* path = nullptr) {
        condition.matchType = FWP_MATCH_EQUAL;
        if (path) {
            Check(FwpmGetAppIdFromFileName0(path, &appId), "Resolve executable identity");
            condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
            condition.conditionValue.type = FWP_BYTE_BLOB_TYPE;
            condition.conditionValue.byteBlob = appId;
        } else {
            Check(static_cast<DWORD>(DeriveAppContainerSidFromAppContainerName(PackageFamily, &packageSid)), "Resolve Claude package identity");
            condition.fieldKey = FWPM_CONDITION_ALE_PACKAGE_ID;
            condition.conditionValue.type = FWP_SID;
            condition.conditionValue.sid = static_cast<SID*>(packageSid);
        }
    }
    ~Identity() {
        if (appId) FwpmFreeMemory0(reinterpret_cast<void**>(&appId));
        if (packageSid) FreeSid(packageSid);
    }
    Identity(const Identity&) = delete;
    Identity& operator=(const Identity&) = delete;
};

UINT64 PopCatInterface() {
    MIB_IF_ROW2 row{};
    Check(ConvertInterfaceAliasToLuid(L"PopCat", &row.InterfaceLuid), "Resolve PopCat adapter");
    Check(GetIfEntry2(&row), "Read PopCat adapter");
    if (std::wstring(row.Description) != L"PopCat Tunnel" || row.InterfaceAndOperStatusFlags.HardwareInterface) {
        throw std::runtime_error("Expected the PopCat virtual adapter.");
    }
    return row.InterfaceLuid.Value;
}

std::vector<GUID> GuardFilters(HANDLE engine, bool includeDisabled = true, bool requireLoopbackException = false) {
    std::vector<GUID> keys;
    GUID providerKey = ProviderKey;
    for (const GUID& layer : ConnectLayers) {
        FWPM_FILTER_ENUM_TEMPLATE0 query{};
        query.providerKey = &providerKey;
        query.layerKey = layer;
        if (includeDisabled) query.flags = FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED;
        query.actionMask = UINT32_MAX;
        HANDLE enumeration = nullptr;
        Check(FwpmFilterCreateEnumHandle0(engine, &query, &enumeration), "Find guard filters");
        FWPM_FILTER0** filters = nullptr;
        UINT32 count = 0;
        const DWORD result = FwpmFilterEnum0(engine, enumeration, UINT32_MAX, &filters, &count);
        FwpmFilterDestroyEnumHandle0(engine, enumeration);
        Check(result, "Read guard filters");

        for (UINT32 i = 0; i < count; ++i) {
            const FWPM_FILTER0& filter = *filters[i];
            if (!IsEqualGUID(filter.subLayerKey, SublayerKey)) continue;
            if (requireLoopbackException) {
                if (filter.action.type != FWP_ACTION_BLOCK || filter.numFilterConditions != 3) continue;
                const auto end = filter.filterCondition + filter.numFilterConditions;
                const bool excludesLoopback = std::any_of(filter.filterCondition, end, [](const auto& condition) {
                    return IsEqualGUID(condition.fieldKey, FWPM_CONDITION_FLAGS) &&
                        condition.matchType == FWP_MATCH_FLAGS_NONE_SET &&
                        condition.conditionValue.type == FWP_UINT32 &&
                        condition.conditionValue.uint32 == FWP_CONDITION_FLAG_IS_LOOPBACK;
                });
                if (!excludesLoopback) continue;
            }
            keys.push_back(filter.filterKey);
        }
        if (filters) FwpmFreeMemory0(reinterpret_cast<void**>(&filters));
    }
    return keys;
}

void CreateGuardObjects(HANDLE engine) {
    FWPM_PROVIDER0 provider{};
    provider.providerKey = ProviderKey;
    provider.displayData.name = GuardName;
    provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
    provider.serviceName = FilteringService;
    DWORD result = FwpmProviderAdd0(engine, &provider, nullptr);
    if (result != FWP_E_ALREADY_EXISTS) Check(result, "Create guard provider");

    GUID providerKey = ProviderKey;
    FWPM_SUBLAYER0 sublayer{};
    sublayer.subLayerKey = SublayerKey;
    sublayer.displayData.name = GuardName;
    sublayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    sublayer.providerKey = &providerKey;
    sublayer.weight = 0xf000;
    result = FwpmSubLayerAdd0(engine, &sublayer, nullptr);
    if (result != FWP_E_ALREADY_EXISTS) Check(result, "Create guard sublayer");
}

void AddBlocks(HANDLE engine, const Identity& identity, UINT64 allowedLuid, bool persistent = true,
    FWP_MATCH_TYPE loopbackMatch = FWP_MATCH_FLAGS_NONE_SET) {
    GUID providerKey = ProviderKey;
    for (const GUID& layer : ConnectLayers) {
        FWPM_FILTER_CONDITION0 conditions[3]{identity.condition, {}, {}};
        conditions[1].fieldKey = FWPM_CONDITION_IP_NEXTHOP_INTERFACE;
        conditions[2].fieldKey = FWPM_CONDITION_FLAGS;
        conditions[2].matchType = loopbackMatch;
        conditions[2].conditionValue.type = FWP_UINT32;
        conditions[2].conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;

        FWPM_FILTER0 filter{};
        filter.displayData.name = GuardName;
        filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
        if (persistent) filter.flags |= FWPM_FILTER_FLAG_PERSISTENT;
        filter.providerKey = &providerKey;
        filter.layerKey = layer;
        filter.subLayerKey = SublayerKey;
        filter.action.type = FWP_ACTION_BLOCK;
        filter.numFilterConditions = ARRAYSIZE(conditions);
        filter.filterCondition = conditions;
        filter.weight.type = FWP_EMPTY;

        conditions[1].matchType = FWP_MATCH_NOT_EQUAL;
        conditions[1].conditionValue.type = FWP_UINT64;
        conditions[1].conditionValue.uint64 = &allowedLuid;
        Check(FwpmFilterAdd0(engine, &filter, nullptr, nullptr), "Block non-PopCat next hops");

        conditions[1].matchType = FWP_MATCH_EQUAL;
        conditions[1].conditionValue.type = FWP_EMPTY;
        Check(FwpmFilterAdd0(engine, &filter, nullptr, nullptr), "Block unknown next hops");
    }
}

void DeleteFilters(HANDLE engine, const std::vector<GUID>& keys) {
    for (const GUID& key : keys) Check(FwpmFilterDeleteByKey0(engine, &key), "Delete guard filter");
}

struct Winsock {
    Winsock() {
        WSADATA data{};
        Check(static_cast<DWORD>(WSAStartup(MAKEWORD(2, 2), &data)), "Start Winsock");
    }
    ~Winsock() { WSACleanup(); }
};

struct TcpSocket {
    SOCKET handle;
    explicit TcpSocket(int family) : handle(socket(family, SOCK_STREAM, IPPROTO_TCP)) {
        if (handle == INVALID_SOCKET) Check(WSAGetLastError(), "Create local test socket");
    }
    ~TcpSocket() { closesocket(handle); }
};

void CheckLocalConnection(int family, sockaddr* address, int length, bool expectBlocked) {
    TcpSocket server(family);
    if (bind(server.handle, address, length) == SOCKET_ERROR || listen(server.handle, 1) == SOCKET_ERROR) {
        Check(WSAGetLastError(), "Listen on loopback");
    }
    if (getsockname(server.handle, address, &length) == SOCKET_ERROR) Check(WSAGetLastError(), "Read loopback test port");
    TcpSocket client(family);
    const int result = connect(client.handle, address, length);
    if (expectBlocked) {
        if (result != SOCKET_ERROR || WSAGetLastError() != WSAEACCES) {
            throw std::runtime_error("The expected WFP block was not observed on loopback.");
        }
    } else if (result == SOCKET_ERROR) {
        Check(WSAGetLastError(), "Connect to loopback before test block");
    }
}

void CheckLoopback(bool expectBlocked) {
    sockaddr_in ipv4{};
    ipv4.sin_family = AF_INET;
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CheckLocalConnection(AF_INET, reinterpret_cast<sockaddr*>(&ipv4), sizeof(ipv4), expectBlocked);

    sockaddr_in6 ipv6{};
    ipv6.sin6_family = AF_INET6;
    ipv6.sin6_addr = in6addr_loopback;
    CheckLocalConnection(AF_INET6, reinterpret_cast<sockaddr*>(&ipv6), sizeof(ipv6), expectBlocked);
}

void SelfTest() {
    Engine persistentEngine;
    const auto before = GuardFilters(persistentEngine.handle, false).size();
    if (!before) throw std::runtime_error("No active Claude protection to verify.");
    if (GuardFilters(persistentEngine.handle, false, true).size() != before) {
        throw std::runtime_error("An installed guard filter does not exclude loopback.");
    }
    wchar_t executable[MAX_PATH]{};
    const DWORD length = GetModuleFileNameW(nullptr, executable, ARRAYSIZE(executable));
    if (!length || length == ARRAYSIZE(executable)) throw std::runtime_error("Could not identify the test executable.");
    Identity testIdentity(executable);
    Winsock winsock;
    CheckLoopback(false);
    const UINT64 popCatLuid = PopCatInterface();
    // Match loopback deliberately for the negative control, scoped to this executable.
    {
        Engine testEngine(true);
        Transaction transaction(testEngine.handle);
        AddBlocks(testEngine.handle, testIdentity, popCatLuid, false, FWP_MATCH_FLAGS_ALL_SET);
        transaction.Commit();
        CheckLoopback(true);
    }
    {
        Engine testEngine(true);
        Transaction transaction(testEngine.handle);
        AddBlocks(testEngine.handle, testIdentity, popCatLuid, false);
        transaction.Commit();
        CheckLoopback(false);
    }
    CheckLoopback(false);
    const auto after = GuardFilters(persistentEngine.handle, false).size();
    if (after != before) throw std::runtime_error("Unexpected change to installed Claude rules during self-test.");
    std::wcout << L"IPv4 and IPv6 loopback: block control passed, guard exception passed, cleanup passed.\n";
    std::wcout << L"Active persistent Claude rules: " << after << L".\n";
}
}

int wmain(int argc, wchar_t** argv) {
    OutputLog log;
    try {
        if (argc >= 4 && std::wstring(argv[1]) == L"--log") {
            log.Open(argv[2]);
            argc -= 2;
            argv += 2;
        }
        if (argc < 2) throw std::runtime_error("Use plan, install, status, self-test, or remove.");
        const std::wstring command = argv[1];
        if (command == L"plan" || command == L"install") {
            if (argc < 4) throw std::runtime_error("Provide both Claude Desktop and Claude Code executable paths.");
            const UINT64 allowedLuid = PopCatInterface();
            Identity package;
            for (int i = 2; i < argc; ++i) {
                Identity program(argv[i]);
                std::wcout << L"Protect: " << argv[i] << L'\n';
            }
            const size_t expected = static_cast<size_t>(argc - 1) * ConnectLayers.size() * 2;
            std::wcout << L"PopCat interface LUID: " << allowedLuid << L". Expected filters: " << expected << L".\n";
            if (command == L"plan") return 0;

            Engine engine;
            Transaction transaction(engine.handle);
            CreateGuardObjects(engine.handle);
            DeleteFilters(engine.handle, GuardFilters(engine.handle));
            AddBlocks(engine.handle, package, allowedLuid);
            for (int i = 2; i < argc; ++i) {
                Identity program(argv[i]);
                AddBlocks(engine.handle, program, allowedLuid);
            }
            transaction.Commit();
            const auto installed = GuardFilters(engine.handle, false, true).size();
            if (installed != expected) throw std::runtime_error("Installed filter count could not be verified.");
            std::wcout << L"Installed " << installed << L" persistent outbound filters with loopback exempted.\n";
            return 0;
        }
        if (command == L"self-test") {
            SelfTest();
            return 0;
        }
        if (command != L"status" && command != L"remove") throw std::runtime_error("Unknown command.");
        Engine engine;
        if (command == L"status") {
            const auto count = GuardFilters(engine.handle).size();
            const auto active = GuardFilters(engine.handle, false).size();
            const auto exemptingLoopback = GuardFilters(engine.handle, false, true).size();
            std::wcout << L"Installed guard filters: " << count << L". Active: " << active
                << L". Exempting loopback: " << exemptingLoopback << L".\n";
            return 0;
        }
        Transaction transaction(engine.handle);
        DeleteFilters(engine.handle, GuardFilters(engine.handle));
        DWORD result = FwpmSubLayerDeleteByKey0(engine.handle, &SublayerKey);
        if (result != FWP_E_SUBLAYER_NOT_FOUND) Check(result, "Remove guard sublayer");
        result = FwpmProviderDeleteByKey0(engine.handle, &ProviderKey);
        if (result != FWP_E_PROVIDER_NOT_FOUND) Check(result, "Remove guard provider");
        transaction.Commit();
        std::wcout << L"Removed Claude outbound protection.\n";
        return 0;
    } catch (const std::exception& error) {
        std::wcerr << error.what() << L'\n';
        return 1;
    }
}
