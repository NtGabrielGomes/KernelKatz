#pragma once
#include <cstdio>
#include <format>
#include <string_view>
#include <windows.h>

namespace detail {
    inline HANDLE hout() noexcept { return GetStdHandle(STD_OUTPUT_HANDLE); }
    inline void set_col(WORD w) noexcept { SetConsoleTextAttribute(hout(), w); }

    template<typename... A>
    inline void log(WORD col, std::string_view tag, std::string_view fmt, A&&... args) noexcept {
        set_col(col);
        std::fwrite(tag.data(), 1, tag.size(), stdout);
        set_col(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        auto s = std::vformat(fmt, std::make_format_args(args...));
        std::fwrite(s.data(), 1, s.size(), stdout);
        std::fputc('\n', stdout);
        std::fflush(stdout);
    }
}

#define log_ok(fmt, ...)  ::detail::log(FOREGROUND_GREEN | FOREGROUND_INTENSITY,                       " [+] ", fmt __VA_OPT__(,) __VA_ARGS__)
#define log_err(fmt, ...) ::detail::log(FOREGROUND_RED   | FOREGROUND_INTENSITY,                       " [-] ", fmt __VA_OPT__(,) __VA_ARGS__)
#define log_inf(fmt, ...) ::detail::log(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,     " [~] ", fmt __VA_OPT__(,) __VA_ARGS__)
