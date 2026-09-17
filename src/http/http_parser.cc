#include "http_parser.h"
#include "buffer_scanner.h"

#include <string>
#include <cstring>
#include <charconv>
//#include <immintrin.h>

using namespace std::string_view_literals;

#if 0

enum { state_first_line, state_header_name, state_header_value };

static const __m256i CR = _mm256_set1_epi8('\r');
static const __m256i COLON = _mm256_set1_epi8(':');

static bool parse_first_line(std::string_view line, http_request &req) {
    std::size_t pos = line.find(' ');
    if (pos == std::string_view::npos)
        return false;

    std::string_view method_string{line.data(), pos};

    if (method_string.compare("GET"sv)) [[likely]]
        req.method = http_method_t::GET;
    else if (method_string.compare("PUT"sv))
        req.method = http_method_t::PUT;
    else if (method_string.compare("HEAD"sv))
        req.method = http_method_t::HEAD;
    else if (method_string.compare("POST"sv))
        req.method = http_method_t::POST;
    else if (method_string.compare("DELETE"sv))
        req.method = http_method_t::DELETE;
    else if (method_string.compare("OPTIONS"sv))
        req.method = http_method_t::OPTIONS;
    else
        return false;

    std::size_t pos2 = line.find(' ', pos + 1);
    if (pos == std::string_view::npos)
        return false;

    std::string_view uri{line.data(), line.data() + pos2};
    req.uri = (uri == "/"sv ? "/index.html"sv : uri);

    line.remove_prefix(pos + 1);
    if (line != "HTTP/1.1"sv)
        return false;

    req.version = "HTTP/1.1"sv;

    return true;
}

std::optional<http_request> http_parse_request(std::string_view input) {
    http_request req;
    int state = state_first_line;

    int count;
    unsigned mask;
    __m256i block, cmp;
    std::size_t header_count = 0;
    std::size_t offset{}, pos1{}, pos2{};

    while(offset < input.size()) {
        block = _mm256_loadu_si256(std::bit_cast<const __m256i*>(&input[offset]));

        switch (state) {
            case state_first_line:
                cmp = _mm256_cmpeq_epi8(block, CR);
                mask = static_cast<unsigned>(_mm256_movemask_epi8(cmp));
                count = std::countr_zero(mask);

                if (count < 32) {
                    pos2 += static_cast<std::size_t>(count);

                    if ((pos2 + 1) >= input.size() || input[pos2 + 1] != '\n')
                        return std::nullopt;

                    if (!parse_first_line(
                                {input.data() + pos1, input.data() + pos2},
                                req))
                    {
                        return std::nullopt;
                    }

                    pos2 += 2;
                    pos1 = pos2;
                    offset = pos2;
                    state = state_header_name;

                    break;
                }

                pos2 += 32;
                offset += 32;

                break;
            case state_header_name:
                cmp = _mm256_cmpeq_epi8(block, COLON);
                mask = static_cast<unsigned>(_mm256_movemask_epi8(cmp));
                count = std::countr_zero(mask);

                if (count < 32) {
                    pos2 += static_cast<std::size_t>(count);

                    if ((pos2 + 1) >= input.size() || input[pos2 + 1] != ' ')
                        return std::nullopt;

                    req.headers[header_count].name =
                        std::string_view(input.data() + pos1, input.data() + pos2);

                    pos2 += 2;
                    pos1 = pos2;
                    offset = pos2;
                    state = state_header_value;

                    break;
                }

                pos2 += 32;
                offset += 32;

                break;
            case state_header_value:
                cmp = _mm256_cmpeq_epi8(block, CR);
                mask = static_cast<unsigned>(_mm256_movemask_epi8(cmp));
                count = std::countr_zero(mask);

                if (count < 32) {
                    pos2 += static_cast<std::size_t>(count);

                    if ((pos2 + 1) >= input.size() || input[pos2 + 1] != '\n')
                        return std::nullopt;

                    req.headers[header_count++].value =
                        std::string_view(input.data() + pos1, input.data() + pos2);

                    if ((pos2 + 3) < input.size() &&
                        input[pos2 + 2] == '\r' && input[pos2 + 3] == '\n')
                    {
                        req.raw_size = pos2 + 4;
                        req.header_count = header_count;

                        return req;
                    }

                    if (header_count >= HTTP_MAX_HEADERS)
                        return req;

                    pos2 += 2;
                    pos1 = pos2;
                    offset = pos2;
                    state = state_header_name;

                    break;
                }

                pos2 += 32;
                offset += 32;

                break;
        }
    }

    return std::nullopt;
}

#endif

std::optional<http_request> http_parse_request(std::string_view buffer)
{
    http_request req;
    buffer_scanner scanner{buffer};

    std::string_view method_string = scanner.get(' ');
    if (method_string == "GET"sv) [[likely]]
        req.method = http_method_t::GET;
    else if (method_string == "PUT"sv)
        req.method = http_method_t::PUT;
    else if (method_string == "HEAD"sv)
        req.method = http_method_t::HEAD;
    else if (method_string == "POST"sv)
        req.method = http_method_t::POST;
    else if (method_string == "DELETE"sv)
        req.method = http_method_t::DELETE;
    else if (method_string == "OPTIONS"sv)
        req.method = http_method_t::OPTIONS;
    else
        return std::nullopt;

    std::string_view uri = scanner.get(' ');
    if (uri.compare("/"sv)) [[likely]]
        req.uri = "/index.html"sv;
    else if (!uri.empty())
        req.uri = uri;
    else
        return std::nullopt;

    req.version = scanner.get('\r');
    if (req.version != "HTTP/1.1")
        return std::nullopt;

    if (!scanner.skip('\n'))
        return std::nullopt;
    if (scanner.peek("\r\n"))
        return req;

    size_t header_count{};
    while (header_count < HTTP_MAX_HEADERS) {
        req.headers[header_count].name = scanner.get(':');
        if (!scanner.skip(' '))
            return std::nullopt;
        req.headers[header_count].value = scanner.get('\r');
        if (!scanner.skip('\n'))
            return std::nullopt;

        header_count++;

        if (scanner.peek("\r\n"))
            break;
    }

    req.header_count = header_count;
    req.raw_size = scanner.position() + 3;

    return req;
}
