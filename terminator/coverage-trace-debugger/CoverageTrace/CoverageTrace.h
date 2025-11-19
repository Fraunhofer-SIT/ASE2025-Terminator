
#pragma once

#define UNICODE
#include <string>
#include <cstdint>
#include <Windows.h>

#include <chrono>

typedef std::uintptr_t address_t;
typedef std::uint8_t byte_t;

struct Options
{
    std::wstring pathToIdaPro;
    std::wstring pathToIdaScript;
    std::wstring pathToTarget;
    std::wstring pathToOutput;
};

struct Module
{
    std::uint32_t id = 0;
    address_t start = 0;
    address_t end = 0;
    std::wstring path;
    bool tracked = false;
};

struct Address
{
    Module const * module;
    address_t offset;
    address_t absolute;
};

namespace std
{
    template<> struct less<Address>
    {
        bool operator() (const Address& lhs, const Address& rhs) const
        {
            return lhs.absolute < rhs.absolute;
        }
    };
}

struct ModuleBasicBlock
{
    std::uint64_t start_ea;
    std::uint64_t base;
    std::uint64_t base_offset;
    std::uint64_t file_offset;
    std::uint64_t segment_start;
    std::uint64_t segment_offset;
    std::uint64_t size;
    byte_t firstByte;
};

struct GlobalBasicBlock
{
    Module const* module;
    ModuleBasicBlock module_block;
};

struct GlobalBasicBlockVisit
{
    using time_point = std::chrono::high_resolution_clock::time_point;

    GlobalBasicBlock global_block;
    time_point time;
    DWORD thread_id;
};

enum class DebugFsmState {
    JustStarted,
    WaitingForInitialBreakpoint,
    WaitingForNextBreakpoint,
    NoMoreBreakpoints
};

struct ThreadInfo {
    DWORD id;
    HANDLE handle;
    std::size_t number;
};
