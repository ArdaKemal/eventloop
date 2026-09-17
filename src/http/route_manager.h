#pragma once

#include <map>
#include <string>
#include <variant>
#include <string_view>

class route_manager {
    typedef void (*upgrade_fn)(int);
    typedef std::string (*resource_fn)(std::string_view data);

    using handler_t = std::variant<upgrade_fn, resource_fn>;

public:
    route_manager() = default;

    template<typename Handler>
    void add(std::string_view uri, Handler handler) {
        routes_.emplace(uri, handler);
    }

    bool try_handle(std::string_view uri, std::string_view data) const {
        auto it = routes_.find(uri);
        if (it == std::end(routes_))
            return false;

        auto handler = std::get<resource_fn>(it->second);
        handler(data);

        return true;
    }

    bool try_handle(std::string_view uri, int fd) const {
        auto it = routes_.find(uri);
        if (it == std::end(routes_))
            return false;

        auto handler = std::get<upgrade_fn>(it->second);
        handler(fd);

        return true;
    }

private:
    std::map<std::string_view, handler_t> routes_;
};
