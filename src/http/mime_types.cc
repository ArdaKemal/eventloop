#include "mime_types.h"

using namespace std::string_view_literals;

auto mime_type_from_path(std::string_view path) -> std::string_view
{
    if (path.ends_with(".html"sv)) [[likely]]
        return "text/html"sv;
    else if (path.ends_with(".css"sv))
        return "text/css"sv;
    else if (path.ends_with(".js"sv))
        return "text/javascript"sv;
    else if (path.ends_with(".txt"sv))
        return "text/plain"sv;
    else if (path.ends_with(".json"sv))
        return "application/json"sv;
    else if (path.ends_with(".png"sv))
        return "image/png"sv;
    else if (path.ends_with(".ico"sv))
        return "image/vnd.microsoft.icon"sv;
    else if (path.ends_with(".jpg"sv) || path.ends_with(".jpeg"sv))
        return "image/jpeg"sv;
    else if (path.ends_with(".mp4"sv))
        return "video/mp4"sv;
    else if (path.ends_with(".webm"sv))
        return "video/webm"sv;
    else
        return "text/plain"sv;
}
