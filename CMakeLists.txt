cmake_minimum_required(VERSION 3.20)
project(event_loop VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

option(EVENTLOOP_HTTP3_INTEROP_TESTS
    "Enable optional outbound HTTP/3 v1/v2 tests using aioquic 1.3.0" OFF)
function(eventloop_register_http3_interop_tests)
    if(BUILD_TESTING AND EVENTLOOP_HTTP3_INTEROP_TESTS)
        find_package(Python3 REQUIRED COMPONENTS Interpreter)
        execute_process(
            COMMAND "${Python3_EXECUTABLE}" -c
                "import aioquic; assert aioquic.__version__ == '1.3.0', 'aioquic 1.3.0 required'"
            RESULT_VARIABLE aioquic_import_result
            ERROR_VARIABLE aioquic_import_error)
        if(NOT aioquic_import_result EQUAL 0)
            message(FATAL_ERROR
                "HTTP/3 interop tests require aioquic==1.3.0 in Python3_EXECUTABLE: ${aioquic_import_error}")
        endif()
        foreach(version v1 v2)
            add_test(NAME http3_outbound_${version}
                COMMAND "${Python3_EXECUTABLE}"
                    "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_http3_outbound.py"
                    --client $<TARGET_FILE:http3_client> --version ${version})
            set_tests_properties(http3_outbound_${version} PROPERTIES
                TIMEOUT 60 LABELS "http3;interop")
        endforeach()
    endif()
endfunction()

if(WIN32)
    include(CTest)
    find_package(Threads REQUIRED)
    option(EVENTLOOP_WINDOWS_TLS "Build Windows TLS/WebSocket support" ON)
    set(EVENTLOOP_CONFIG_NEEDS_OPENSSL ON)
    find_package(OpenSSL 3.5 REQUIRED COMPONENTS Crypto SSL)
    set(EVENTLOOP_QUIC_TEST_ENV
        "PATH=path_list_prepend:${OPENSSL_ROOT_DIR}/bin")
    add_library(eventloop
        src/event_loop.cc
        src/quic/packet_protection.cc
        src/quic/protected_packet.cc
        src/quic/connection_core.cc
        src/quic/udp_endpoint.cc
        src/quic/key_update.cc
        src/quic/retry_packet.cc
        src/quic/retry_token.cc
        src/quic/tls_provider.cc
        src/quic/quic_endpoint.cc
        src/http3/server.cc
        src/http3/qpack.cc
        src/windows/file_operation.cc
        src/executor/single_thread_executor.cc
        src/executor/multi_thread_executor.cc
        src/tcp_acceptor.cc
        src/tcp_stream.cc
        src/udp_socket.cc
        src/util/arg_parser.cc
        src/http/request.cc
        src/http/mime_types.cc
        src/http/resource.cc
        src/http/directory_listing.cc
        src/http/session.cc
        src/http/server.cc
        src/windows/iocp_loop.cc
        src/windows/http_file_operations.cc
        src/windows/socket_operations.cc
    )
    if(EVENTLOOP_WINDOWS_TLS)
        target_sources(eventloop PRIVATE
            src/tls_stream.cc
            src/ws/web_socket.cpp
            src/http2/connection.h
            src/http2/connection.cc
            src/http2/client.cc
            src/http2/hpack.h
            src/http2/hpack.cc
            src/http2/session.h
            src/http2/session.cc
        )
        target_compile_definitions(eventloop PUBLIC EVENTLOOP_WINDOWS_TLS=1)
    endif()
    add_library(eventloop::eventloop ALIAS eventloop)
    target_include_directories(eventloop PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    )
    target_include_directories(eventloop PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_compile_features(eventloop PUBLIC cxx_std_23)
    target_compile_definitions(eventloop PRIVATE NOMINMAX)
    target_link_libraries(eventloop PUBLIC ws2_32 mswsock Threads::Threads
        PRIVATE crypt32 OpenSSL::SSL OpenSSL::Crypto)
    if(BUILD_SHARED_LIBS)
        target_compile_definitions(eventloop PRIVATE EVENTLOOP_WINDOWS_SHARED=1)
    endif()
    if(MSVC)
        target_compile_options(eventloop PRIVATE /W4)
    endif()
    if(BUILD_TESTING)
        add_executable(http_api_test tests/http_api.cc)
        target_link_libraries(http_api_test PRIVATE eventloop::eventloop OpenSSL::Crypto)
        add_test(NAME http_api COMMAND http_api_test)
        set_tests_properties(http_api PROPERTIES TIMEOUT 10)
        if(EVENTLOOP_WINDOWS_TLS)
            set_tests_properties(http_api PROPERTIES ENVIRONMENT_MODIFICATION
                "PATH=path_list_prepend:${OPENSSL_ROOT_DIR}/bin")
        endif()

        add_executable(coroutine_smoke_test tests/coroutine_smoke.cc)
        target_link_libraries(coroutine_smoke_test PRIVATE eventloop::eventloop)
        add_test(NAME coroutine_smoke COMMAND coroutine_smoke_test)

        add_executable(event_loop_test tests/event_loop.cc)
        target_link_libraries(event_loop_test PRIVATE eventloop::eventloop)
        add_test(NAME event_loop COMMAND event_loop_test)

        add_executable(quic_varint_test tests/quic_varint.cc)
        target_include_directories(quic_varint_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_varint_test PRIVATE eventloop::eventloop)
        add_test(NAME quic_varint COMMAND quic_varint_test)

        add_executable(quic_transport_parameters_test
            tests/quic_transport_parameters.cc)
        target_include_directories(quic_transport_parameters_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_transport_parameters_test PRIVATE
            eventloop::eventloop)
        add_test(NAME quic_transport_parameters
            COMMAND quic_transport_parameters_test)

        add_executable(quic_packet_header_test tests/quic_packet_header.cc)
        target_include_directories(quic_packet_header_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_packet_header_test PRIVATE
            eventloop::eventloop)
        add_test(NAME quic_packet_header COMMAND quic_packet_header_test)

        add_executable(quic_frames_test tests/quic_frames.cc)
        target_include_directories(quic_frames_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_frames_test PRIVATE eventloop::eventloop)
        add_test(NAME quic_frames COMMAND quic_frames_test)

        add_executable(quic_frame_encoder_test
            tests/quic_frame_encoder.cc)
        target_include_directories(quic_frame_encoder_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_frame_encoder_test PRIVATE
            eventloop::eventloop)
        add_test(NAME quic_frame_encoder COMMAND quic_frame_encoder_test)

        add_executable(quic_frame_policy_test tests/quic_frame_policy.cc)
        target_include_directories(quic_frame_policy_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_frame_policy_test PRIVATE
            eventloop::eventloop)
        add_test(NAME quic_frame_policy COMMAND quic_frame_policy_test)

        add_executable(quic_crypto_buffer_test tests/quic_crypto_buffer.cc)
        target_include_directories(quic_crypto_buffer_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_crypto_buffer_test PRIVATE
            eventloop::eventloop)
        add_test(NAME quic_crypto_buffer COMMAND quic_crypto_buffer_test)

        add_executable(quic_crypto_send_buffer_test
            tests/quic_crypto_send_buffer.cc)
        target_include_directories(quic_crypto_send_buffer_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_crypto_send_buffer_test PRIVATE
            eventloop::eventloop)
        add_test(NAME quic_crypto_send_buffer
            COMMAND quic_crypto_send_buffer_test)

        add_executable(quic_stream_receive_test
            tests/quic_stream_receive.cc)
        target_include_directories(quic_stream_receive_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_stream_receive_test PRIVATE
            eventloop::eventloop)
        add_test(NAME quic_stream_receive COMMAND quic_stream_receive_test)

        add_executable(quic_stream_send_buffer_test
            tests/quic_stream_send_buffer.cc)
        target_include_directories(quic_stream_send_buffer_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_stream_send_buffer_test PRIVATE
            eventloop::eventloop)
        add_test(NAME quic_stream_send_buffer
            COMMAND quic_stream_send_buffer_test)

        add_executable(quic_version_negotiation_test
            tests/quic_version_negotiation.cc)
        target_include_directories(quic_version_negotiation_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_version_negotiation_test PRIVATE
            eventloop::eventloop)
        add_test(NAME quic_version_negotiation
            COMMAND quic_version_negotiation_test)

        add_executable(quic_recovery_timer_test tests/quic_recovery_timer.cc)
        target_include_directories(quic_recovery_timer_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_recovery_timer_test PRIVATE
            eventloop::eventloop)
        add_test(NAME quic_recovery_timer COMMAND quic_recovery_timer_test)

        add_executable(quic_ack_ranges_test tests/quic_ack_ranges.cc)
        target_include_directories(quic_ack_ranges_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_ack_ranges_test PRIVATE eventloop::eventloop)
        add_test(NAME quic_ack_ranges COMMAND quic_ack_ranges_test)

        add_executable(quic_received_packet_ranges_test
            tests/quic_received_packet_ranges.cc)
        target_include_directories(quic_received_packet_ranges_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_received_packet_ranges_test PRIVATE
            eventloop::eventloop)
        add_test(NAME quic_received_packet_ranges
            COMMAND quic_received_packet_ranges_test)

        add_executable(quic_stream_registry_test tests/quic_stream_registry.cc)
        target_include_directories(quic_stream_registry_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_stream_registry_test PRIVATE
            eventloop::eventloop)
        add_test(NAME quic_stream_registry COMMAND quic_stream_registry_test)

        add_executable(quic_datagram_queue_test tests/quic_datagram_queue.cc)
        target_include_directories(quic_datagram_queue_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_datagram_queue_test PRIVATE
            eventloop::eventloop)
        add_test(NAME quic_datagram_queue COMMAND quic_datagram_queue_test)

        add_executable(quic_flow_control_test tests/quic_flow_control.cc)
        target_include_directories(quic_flow_control_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_flow_control_test PRIVATE
            eventloop::eventloop)
        add_test(NAME quic_flow_control COMMAND quic_flow_control_test)

        add_executable(quic_path_validation_test
            tests/quic_path_validation.cc)
        target_include_directories(quic_path_validation_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_path_validation_test PRIVATE
            eventloop::eventloop)
        add_test(NAME quic_path_validation COMMAND quic_path_validation_test)

        add_executable(quic_connection_id_registry_test
            tests/quic_connection_id_registry.cc)
        target_include_directories(quic_connection_id_registry_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_connection_id_registry_test PRIVATE
            eventloop::eventloop)
        add_test(NAME quic_connection_id_registry
            COMMAND quic_connection_id_registry_test)

        add_executable(quic_local_connection_id_registry_test
            tests/quic_local_connection_id_registry.cc)
        target_include_directories(quic_local_connection_id_registry_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_local_connection_id_registry_test PRIVATE
            eventloop::eventloop)
        add_test(NAME quic_local_connection_id_registry
            COMMAND quic_local_connection_id_registry_test)

        add_executable(quic_stream_state_test tests/quic_stream_state.cc)
        target_include_directories(quic_stream_state_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_stream_state_test PRIVATE eventloop::eventloop)
        add_test(NAME quic_stream_state COMMAND quic_stream_state_test)

        add_executable(quic_connection_lifecycle_test
            tests/quic_connection_lifecycle.cc)
        target_include_directories(quic_connection_lifecycle_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_connection_lifecycle_test PRIVATE
            eventloop::eventloop)
        add_test(NAME quic_connection_lifecycle
            COMMAND quic_connection_lifecycle_test)

        add_executable(quic_stateless_reset_test
            tests/quic_stateless_reset.cc)
        target_include_directories(quic_stateless_reset_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_stateless_reset_test PRIVATE
            eventloop::eventloop)
        add_test(NAME quic_stateless_reset COMMAND quic_stateless_reset_test)

        add_executable(quic_ecn_state_test tests/quic_ecn_state.cc)
        target_include_directories(quic_ecn_state_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_ecn_state_test PRIVATE eventloop::eventloop)
        add_test(NAME quic_ecn_state COMMAND quic_ecn_state_test)

        add_executable(quic_retry_token_test
            tests/quic_retry_token.cc)
        target_include_directories(quic_retry_token_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_retry_token_test PRIVATE
            eventloop::eventloop OpenSSL::Crypto)
        add_test(NAME quic_retry_token COMMAND quic_retry_token_test)
        set_tests_properties(quic_retry_token PROPERTIES
            ENVIRONMENT_MODIFICATION
            "${EVENTLOOP_QUIC_TEST_ENV}")

        add_executable(quic_retry_packet_test tests/quic_retry_packet.cc)
        target_include_directories(quic_retry_packet_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_retry_packet_test PRIVATE
            eventloop::eventloop OpenSSL::Crypto)
        add_test(NAME quic_retry_packet COMMAND quic_retry_packet_test)
        set_tests_properties(quic_retry_packet PROPERTIES
            ENVIRONMENT_MODIFICATION "${EVENTLOOP_QUIC_TEST_ENV}")

        add_executable(quic_transport_parameter_validation_test
            tests/quic_transport_parameter_validation.cc)
        target_include_directories(quic_transport_parameter_validation_test
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_transport_parameter_validation_test PRIVATE
            eventloop::eventloop)
        add_test(NAME quic_transport_parameter_validation
            COMMAND quic_transport_parameter_validation_test)

        add_executable(quic_key_update_test tests/quic_key_update.cc)
        target_include_directories(quic_key_update_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_key_update_test PRIVATE
            eventloop::eventloop OpenSSL::Crypto)
        add_test(NAME quic_key_update COMMAND quic_key_update_test)
        set_tests_properties(quic_key_update PROPERTIES
            ENVIRONMENT_MODIFICATION
            "${EVENTLOOP_QUIC_TEST_ENV}")

        add_executable(quic_packet_protection_context_test
            tests/quic_packet_protection_context.cc)
        target_include_directories(quic_packet_protection_context_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_packet_protection_context_test PRIVATE
            eventloop::eventloop OpenSSL::Crypto)
        add_test(NAME quic_packet_protection_context
            COMMAND quic_packet_protection_context_test)
        set_tests_properties(quic_packet_protection_context PROPERTIES
            ENVIRONMENT_MODIFICATION "${EVENTLOOP_QUIC_TEST_ENV}")

        add_executable(quic_loss_detection_test tests/quic_loss_detection.cc)
        target_include_directories(quic_loss_detection_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_loss_detection_test PRIVATE
            eventloop::eventloop)
        add_test(NAME quic_loss_detection COMMAND quic_loss_detection_test)

        add_executable(quic_sent_packet_history_test
            tests/quic_sent_packet_history.cc)
        target_include_directories(quic_sent_packet_history_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_sent_packet_history_test PRIVATE
            eventloop::eventloop)
        add_test(NAME quic_sent_packet_history
            COMMAND quic_sent_packet_history_test)

        add_executable(quic_recovery_orchestration_test
            tests/quic_recovery_orchestration.cc)
        target_include_directories(quic_recovery_orchestration_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_recovery_orchestration_test PRIVATE
            eventloop::eventloop)
        add_test(NAME quic_recovery_orchestration
            COMMAND quic_recovery_orchestration_test)

        add_executable(quic_congestion_control_test
            tests/quic_congestion_control.cc)
        target_include_directories(quic_congestion_control_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_congestion_control_test PRIVATE
            eventloop::eventloop)
        add_test(NAME quic_congestion_control
            COMMAND quic_congestion_control_test)

        add_executable(quic_path_recovery_state_test
            tests/quic_path_recovery_state.cc)
        target_include_directories(quic_path_recovery_state_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_path_recovery_state_test PRIVATE
            eventloop::eventloop)
        add_test(NAME quic_path_recovery_state
            COMMAND quic_path_recovery_state_test)

        add_executable(quic_grease_quic_bit_test
            tests/quic_grease_quic_bit.cc)
        target_include_directories(quic_grease_quic_bit_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_grease_quic_bit_test PRIVATE
            eventloop::eventloop OpenSSL::Crypto)
        add_test(NAME quic_grease_quic_bit
            COMMAND quic_grease_quic_bit_test)
        set_tests_properties(quic_grease_quic_bit PROPERTIES
            ENVIRONMENT_MODIFICATION "${EVENTLOOP_QUIC_TEST_ENV}")

        add_executable(quic_public_api_test tests/quic_public_api.cc)
        target_include_directories(quic_public_api_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_public_api_test PRIVATE
            eventloop::eventloop OpenSSL::SSL OpenSSL::Crypto)
        add_test(NAME quic_public_api COMMAND quic_public_api_test)
        set_tests_properties(quic_public_api PROPERTIES TIMEOUT 20
            ENVIRONMENT_MODIFICATION "${EVENTLOOP_QUIC_TEST_ENV}")

        add_executable(quic_packet_protection_test
            tests/quic_packet_protection.cc)
        target_include_directories(quic_packet_protection_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_packet_protection_test PRIVATE
            eventloop::eventloop)
        add_test(NAME quic_packet_protection
            COMMAND quic_packet_protection_test)
        set_tests_properties(quic_packet_protection PROPERTIES
            ENVIRONMENT_MODIFICATION
            "${EVENTLOOP_QUIC_TEST_ENV}")

        add_executable(quic_protected_packet_test
            tests/quic_protected_packet.cc)
        target_include_directories(quic_protected_packet_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_protected_packet_test PRIVATE
            eventloop::eventloop)
        add_test(NAME quic_protected_packet
            COMMAND quic_protected_packet_test)
        set_tests_properties(quic_protected_packet PROPERTIES
            ENVIRONMENT_MODIFICATION
            "${EVENTLOOP_QUIC_TEST_ENV}")

        add_executable(quic_tls_test tests/quic_tls.cc)
        target_include_directories(quic_tls_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_tls_test PRIVATE
            eventloop::eventloop OpenSSL::SSL OpenSSL::Crypto)
        add_test(NAME quic_tls COMMAND quic_tls_test)
        set_tests_properties(quic_tls PROPERTIES ENVIRONMENT_MODIFICATION
            "${EVENTLOOP_QUIC_TEST_ENV}")

        add_executable(quic_connection_core_test
            tests/quic_connection_core.cc)
        target_include_directories(quic_connection_core_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_connection_core_test PRIVATE
            eventloop::eventloop OpenSSL::SSL OpenSSL::Crypto)
        add_test(NAME quic_connection_core COMMAND quic_connection_core_test)
        set_tests_properties(quic_connection_core PROPERTIES
            ENVIRONMENT_MODIFICATION "${EVENTLOOP_QUIC_TEST_ENV}")

        add_executable(quic_connection_test tests/quic_connection.cc)
        target_include_directories(quic_connection_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_connection_test PRIVATE
            eventloop::eventloop OpenSSL::SSL OpenSSL::Crypto)
        add_test(NAME quic_connection COMMAND quic_connection_test)
        set_tests_properties(quic_connection PROPERTIES
            ENVIRONMENT_MODIFICATION "${EVENTLOOP_QUIC_TEST_ENV}")

        add_executable(quic_packet_scheduler_test tests/quic_packet_scheduler.cc)
        target_include_directories(quic_packet_scheduler_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_packet_scheduler_test PRIVATE
            eventloop::eventloop OpenSSL::SSL OpenSSL::Crypto)
        add_test(NAME quic_packet_scheduler COMMAND quic_packet_scheduler_test)
        set_tests_properties(quic_packet_scheduler PROPERTIES
            ENVIRONMENT_MODIFICATION "${EVENTLOOP_QUIC_TEST_ENV}")

        add_executable(quic_endpoint_router_test
            tests/quic_endpoint_router.cc)
        target_include_directories(quic_endpoint_router_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_endpoint_router_test PRIVATE
            eventloop::eventloop)
        add_test(NAME quic_endpoint_router COMMAND quic_endpoint_router_test)

        add_executable(quic_connection_driver_test tests/quic_connection_driver.cc)
        target_include_directories(quic_connection_driver_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_connection_driver_test PRIVATE eventloop::eventloop OpenSSL::SSL OpenSSL::Crypto)
        add_test(NAME quic_connection_driver COMMAND quic_connection_driver_test)
        set_tests_properties(quic_connection_driver PROPERTIES TIMEOUT 15 ENVIRONMENT_MODIFICATION "${EVENTLOOP_QUIC_TEST_ENV}")

        add_executable(quic_driver_failure_test tests/quic_driver_failure.cc)
        target_link_libraries(quic_driver_failure_test PRIVATE
            eventloop::eventloop OpenSSL::SSL OpenSSL::Crypto)
        add_test(NAME quic_driver_failure COMMAND quic_driver_failure_test)
        set_tests_properties(quic_driver_failure PROPERTIES TIMEOUT 15
            ENVIRONMENT_MODIFICATION "${EVENTLOOP_QUIC_TEST_ENV}")

        add_executable(http3_frames_test tests/http3_frames.cc)
        target_include_directories(http3_frames_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(http3_frames_test PRIVATE eventloop::eventloop)
        add_test(NAME http3_frames COMMAND http3_frames_test)

        add_executable(http3_qpack_test tests/http3_qpack.cc src/http3/qpack.cc)
        target_include_directories(http3_qpack_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(http3_qpack_test PRIVATE eventloop::eventloop)
        add_test(NAME http3_qpack COMMAND http3_qpack_test)

        add_executable(quic_udp_endpoint_test tests/quic_udp_endpoint.cc)
        target_include_directories(quic_udp_endpoint_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(quic_udp_endpoint_test PRIVATE
            eventloop::eventloop OpenSSL::Crypto)
        add_test(NAME quic_udp_endpoint COMMAND quic_udp_endpoint_test)
        set_tests_properties(quic_udp_endpoint PROPERTIES
            ENVIRONMENT_MODIFICATION "${EVENTLOOP_QUIC_TEST_ENV}")

        add_executable(executor_test tests/executor.cc)
        target_include_directories(executor_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(executor_test PRIVATE eventloop::eventloop)
        add_test(NAME executor COMMAND executor_test)
        set_tests_properties(executor PROPERTIES TIMEOUT 30)

        add_executable(task_test tests/task.cc)
        target_link_libraries(task_test PRIVATE eventloop::eventloop)
        if(BUILD_SHARED_LIBS)
            target_compile_definitions(task_test PRIVATE
                EVENTLOOP_TEST_SHARED_LIBRARY=1)
        endif()
        add_test(NAME task COMMAND task_test)

        add_executable(task_composition_test tests/task_composition.cc)
        target_link_libraries(task_composition_test PRIVATE eventloop::eventloop)
        add_test(NAME task_composition COMMAND task_composition_test)

        add_executable(task_handle_test tests/task_handle.cc)
        target_link_libraries(task_handle_test PRIVATE eventloop::eventloop)
        add_test(NAME task_handle COMMAND task_handle_test)

        add_executable(file_io_test tests/file_io.cc)
        target_link_libraries(file_io_test PRIVATE eventloop::eventloop)
        add_test(NAME file_io COMMAND file_io_test)
        set_tests_properties(file_io PROPERTIES TIMEOUT 10)

        add_executable(coroutine_tcp_test tests/tcp_coroutine.cc)
        target_link_libraries(coroutine_tcp_test PRIVATE eventloop::eventloop)
        add_test(NAME coroutine_tcp COMMAND coroutine_tcp_test)
        set_tests_properties(coroutine_tcp PROPERTIES TIMEOUT 10)

        add_executable(coroutine_udp_test tests/udp_coroutine.cc)
        target_link_libraries(coroutine_udp_test PRIVATE eventloop::eventloop)
        add_test(NAME coroutine_udp COMMAND coroutine_udp_test)
        set_tests_properties(coroutine_udp PROPERTIES TIMEOUT 10)

        add_executable(socket_api_test tests/socket_api.cc)
        target_link_libraries(socket_api_test PRIVATE eventloop::eventloop OpenSSL::Crypto)
        if(EVENTLOOP_WINDOWS_TLS)
            target_compile_definitions(socket_api_test PRIVATE EVENTLOOP_TEST_TLS=1)
        endif()
        add_test(NAME socket_api COMMAND socket_api_test)
        set_tests_properties(socket_api PROPERTIES TIMEOUT 10)
        if(EVENTLOOP_WINDOWS_TLS)
            set_tests_properties(socket_api PROPERTIES ENVIRONMENT_MODIFICATION
                "PATH=path_list_prepend:${OPENSSL_ROOT_DIR}/bin")
        endif()

        add_executable(windows_iocp_test tests/windows_iocp.cc)
        target_include_directories(windows_iocp_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(windows_iocp_test PRIVATE eventloop)
        if(BUILD_SHARED_LIBS)
            target_compile_definitions(windows_iocp_test PRIVATE
                EVENTLOOP_WINDOWS_SHARED=1)
        endif()
        add_test(NAME windows_iocp COMMAND windows_iocp_test)
        set_tests_properties(windows_iocp PROPERTIES TIMEOUT 10)

        add_executable(windows_socket_operations_test
            tests/windows_socket_operations.cc)
        target_link_libraries(windows_socket_operations_test PRIVATE eventloop)
        add_test(NAME windows_socket_operations
                 COMMAND windows_socket_operations_test)
        set_tests_properties(windows_socket_operations PROPERTIES TIMEOUT 10)

        add_executable(windows_iocp_lifecycle_test
            tests/windows_iocp_lifecycle.cc)
        target_include_directories(windows_iocp_lifecycle_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(windows_iocp_lifecycle_test PRIVATE eventloop)
        add_test(NAME windows_iocp_lifecycle
                 COMMAND windows_iocp_lifecycle_test)
        set_tests_properties(windows_iocp_lifecycle PROPERTIES TIMEOUT 10)
        if(EVENTLOOP_WINDOWS_TLS)
            add_executable(web_socket_test tests/web_socket.cc)
            target_link_libraries(web_socket_test PRIVATE eventloop::eventloop)
            add_test(NAME web_socket COMMAND web_socket_test)

            add_executable(http2_hpack_test tests/http2_hpack.cc)
            target_include_directories(http2_hpack_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
            target_link_libraries(http2_hpack_test PRIVATE eventloop::eventloop)
            add_test(NAME http2_hpack COMMAND http2_hpack_test)
        endif()

        get_property(eventloop_windows_tests DIRECTORY PROPERTY TESTS)
        set_tests_properties(${eventloop_windows_tests} PROPERTIES
            ENVIRONMENT_MODIFICATION "${EVENTLOOP_QUIC_TEST_ENV}")
    endif()

    add_executable(tcp_echo examples/tcp_echo.cc)
    target_link_libraries(tcp_echo PRIVATE eventloop::eventloop)

    if(EVENTLOOP_WINDOWS_TLS)
        add_executable(websocket_echo_server examples/websocket_echo_server.cc)
        target_link_libraries(websocket_echo_server PRIVATE eventloop::eventloop OpenSSL::Crypto)
    endif()

    add_executable(quic_echo_server examples/quic_echo_server.cc)
    target_link_libraries(quic_echo_server PRIVATE eventloop::eventloop)

    add_executable(http_benchmark_server examples/http_benchmark_server.cc)
    target_link_libraries(http_benchmark_server PRIVATE eventloop::eventloop)

    add_executable(file_io_benchmark benchmark/file_io_benchmark.cc)
    target_link_libraries(file_io_benchmark PRIVATE eventloop::eventloop)

    if(EVENTLOOP_WINDOWS_TLS)
        add_executable(http_server examples/http_server.cc)
        target_link_libraries(http_server PRIVATE eventloop::eventloop)

        add_executable(tls_echo examples/tls_echo.cc)
        target_link_libraries(tls_echo PRIVATE eventloop::eventloop)

        add_executable(http_client
            examples/http_client.cc
            examples/http_client_url.cc
            examples/http_client_resolve.cc)
        target_link_libraries(http_client PRIVATE eventloop::eventloop)
        add_executable(http2_client examples/http2_client.cc)
        target_link_libraries(http2_client PRIVATE eventloop::eventloop)

        add_executable(websocket_client
            examples/websocket_client.cc
            examples/http_client_url.cc
            examples/http_client_resolve.cc)
        target_link_libraries(websocket_client PRIVATE eventloop::eventloop OpenSSL::Crypto)
    endif()

    add_executable(http3_client
        examples/http3_client.cc
        examples/http3_client_session.cc
        examples/http_client_url.cc
        examples/http_client_resolve.cc
        src/http3/qpack.cc)
    target_include_directories(http3_client PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(http3_client PRIVATE eventloop::eventloop)
    add_executable(http3_file_server examples/http3_file_server.cc)
    target_link_libraries(http3_file_server PRIVATE eventloop::eventloop)

    add_executable(executor_benchmark benchmark/executor_benchmark.cc)
    target_link_libraries(executor_benchmark PRIVATE eventloop::eventloop)
    add_executable(event_loop_benchmark benchmark/event_loop_benchmark.cc)
    target_link_libraries(event_loop_benchmark PRIVATE eventloop::eventloop)
    add_executable(coroutine_socket_benchmark
        benchmark/coroutine_socket_benchmark.cc)
    target_link_libraries(coroutine_socket_benchmark PRIVATE eventloop::eventloop)
    if(MSVC)
        target_compile_options(executor_benchmark PRIVATE /W4)
        target_compile_options(event_loop_benchmark PRIVATE /W4)
        target_compile_options(coroutine_socket_benchmark PRIVATE /W4)
    endif()

    set(eventloop_package_dir "${CMAKE_INSTALL_LIBDIR}/cmake/eventloop")
    install(TARGETS eventloop EXPORT eventloopTargets
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    )
    set(eventloop_windows_excluded_headers)
    if(NOT EVENTLOOP_WINDOWS_TLS)
        list(APPEND eventloop_windows_excluded_headers
            PATTERN "tls_context.h" EXCLUDE
            PATTERN "tls_stream.h" EXCLUDE
            PATTERN "http2" EXCLUDE
            PATTERN "ws" EXCLUDE
        )
    endif()
    install(DIRECTORY include/eventloop/
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/eventloop"
        ${eventloop_windows_excluded_headers}
    )
    install(EXPORT eventloopTargets
        FILE eventloopTargets.cmake
        NAMESPACE eventloop::
        DESTINATION "${eventloop_package_dir}"
    )
    configure_package_config_file(
        cmake/eventloopConfig.cmake.in
        "${CMAKE_CURRENT_BINARY_DIR}/eventloopConfig.cmake"
        INSTALL_DESTINATION "${eventloop_package_dir}"
    )
    write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/eventloopConfigVersion.cmake"
        VERSION "${PROJECT_VERSION}"
        COMPATIBILITY SameMajorVersion
    )
    install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/eventloopConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/eventloopConfigVersion.cmake"
        DESTINATION "${eventloop_package_dir}"
    )
    eventloop_register_http3_interop_tests()
    return()
endif()

set(EVENTLOOP_CONFIG_NEEDS_OPENSSL ON)
find_package(OpenSSL 3.5 REQUIRED COMPONENTS Crypto SSL)
find_package(Threads REQUIRED)
include(CTest)

add_library(eventloop
    include/eventloop/event_loop.h
    include/eventloop/executor.h
    include/eventloop/file_io.h
    include/eventloop/http/mime_types.h
    include/eventloop/http/request.h
    include/eventloop/http2/client.h
    include/eventloop/http/server.h
    include/eventloop/http/http3_server.h
    include/eventloop/http/session.h
    include/eventloop/ip_endpoint.h
    include/eventloop/tcp_acceptor.h
    include/eventloop/tcp_stream.h
    include/eventloop/task.h
    include/eventloop/task_composition.h
    include/eventloop/tls_context.h
    include/eventloop/tls_stream.h
    include/eventloop/unique_fd.h
    include/eventloop/udp_socket.h
    include/eventloop/util/arg_parser.h
    include/eventloop/ws/web_socket.h
    src/linux/file_operation.cc
    src/linux/http_file_operations.cc
    src/event_loop.cc
    src/quic/packet_protection.cc
    src/quic/protected_packet.cc
    src/quic/connection_core.cc
    src/quic/udp_endpoint.cc
    src/quic/key_update.cc
    src/quic/retry_packet.cc
    src/quic/retry_token.cc
    src/quic/tls_provider.cc
    src/quic/quic_endpoint.cc
    src/http3/server.cc
    src/http3/qpack.cc
    src/executor/single_thread_executor.cc
    src/executor/multi_thread_executor.cc
    src/http/directory_listing.cc
    src/http/mime_types.cc
    src/http/request.cc
    src/http/resource.h
    src/http/resource.cc
    src/http/server.cc
    src/http/session.cc
    src/http2/connection.h
    src/http2/connection.cc
    src/http2/client.cc
    src/http2/hpack.h
    src/http2/hpack.cc
    src/http2/session.h
    src/http2/session.cc
    src/tcp_acceptor.cc
    src/tcp_stream.cc
    src/tls_stream.cc
    src/util/arg_parser.cc
    src/udp_socket.cc
    src/ws/web_socket.cpp
)

if(APPLE)
    target_sources(eventloop PRIVATE
        src/macos/kqueue_loop.cc
        src/macos/socket_operations.cc
    )
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_sources(eventloop PRIVATE
        src/linux/epoll_loop.cc
        src/linux/socket_operations.cc
    )
else()
    message(FATAL_ERROR "eventloop supports Linux, macOS, and Windows")
endif()

add_library(eventloop::eventloop ALIAS eventloop)

target_include_directories(eventloop
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_include_directories(eventloop PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_features(eventloop PUBLIC cxx_std_23)
target_link_libraries(eventloop PUBLIC Threads::Threads
    PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_compile_options(eventloop PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

set(eventloop_package_dir "${CMAKE_INSTALL_LIBDIR}/cmake/eventloop")

install(TARGETS eventloop EXPORT eventloopTargets
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)
install(DIRECTORY include/eventloop DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
install(EXPORT eventloopTargets
    FILE eventloopTargets.cmake
    NAMESPACE eventloop::
    DESTINATION "${eventloop_package_dir}"
)

configure_package_config_file(
    cmake/eventloopConfig.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/eventloopConfig.cmake"
    INSTALL_DESTINATION "${eventloop_package_dir}"
)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/eventloopConfigVersion.cmake"
    VERSION "${PROJECT_VERSION}"
    COMPATIBILITY SameMajorVersion
)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/eventloopConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/eventloopConfigVersion.cmake"
    DESTINATION "${eventloop_package_dir}"
)

add_executable(tcp_echo examples/tcp_echo.cc)
target_link_libraries(tcp_echo PRIVATE eventloop::eventloop)
target_compile_options(tcp_echo PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_executable(websocket_echo_server examples/websocket_echo_server.cc)
target_link_libraries(websocket_echo_server PRIVATE eventloop::eventloop OpenSSL::Crypto)
target_compile_options(websocket_echo_server PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_executable(quic_echo_server examples/quic_echo_server.cc)
target_link_libraries(quic_echo_server PRIVATE eventloop::eventloop)
target_compile_options(quic_echo_server PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(quic_echo_server PRIVATE -Wno-mismatched-new-delete)
endif()

add_executable(tls_echo examples/tls_echo.cc)
target_link_libraries(tls_echo PRIVATE eventloop::eventloop)
target_compile_options(tls_echo PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_executable(http_server examples/http_server.cc)
target_link_libraries(http_server PRIVATE eventloop::eventloop)
target_compile_options(http_server PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_executable(http_client
    examples/http_client.cc
    examples/http_client_url.cc
    examples/http_client_resolve.cc
)
target_link_libraries(http_client PRIVATE eventloop::eventloop)
target_compile_options(http_client PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
add_executable(http2_client examples/http2_client.cc)
target_link_libraries(http2_client PRIVATE eventloop::eventloop)
target_compile_options(http2_client PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_executable(websocket_client
    examples/websocket_client.cc
    examples/http_client_url.cc
    examples/http_client_resolve.cc
)
target_link_libraries(websocket_client PRIVATE eventloop::eventloop OpenSSL::Crypto)
target_compile_options(websocket_client PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_executable(http3_client
    examples/http3_client.cc
    examples/http3_client_session.cc
    examples/http_client_url.cc
    examples/http_client_resolve.cc
    src/http3/qpack.cc)
target_include_directories(http3_client PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(http3_client PRIVATE eventloop::eventloop)
target_compile_options(http3_client PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
add_executable(http3_file_server examples/http3_file_server.cc)
target_link_libraries(http3_file_server PRIVATE eventloop::eventloop)
target_compile_options(http3_file_server PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_executable(http_benchmark_server examples/http_benchmark_server.cc)
target_link_libraries(http_benchmark_server PRIVATE eventloop::eventloop)
target_compile_options(http_benchmark_server PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_executable(executor_benchmark benchmark/executor_benchmark.cc)
target_link_libraries(executor_benchmark PRIVATE eventloop::eventloop)
target_compile_options(executor_benchmark PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_executable(event_loop_benchmark benchmark/event_loop_benchmark.cc)
target_link_libraries(event_loop_benchmark PRIVATE eventloop::eventloop)
target_compile_options(event_loop_benchmark PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

add_executable(file_io_benchmark benchmark/file_io_benchmark.cc)
target_link_libraries(file_io_benchmark PRIVATE eventloop::eventloop)
target_compile_options(file_io_benchmark PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(file_io_benchmark PRIVATE -Wno-mismatched-new-delete)
endif()

add_executable(coroutine_socket_benchmark benchmark/coroutine_socket_benchmark.cc)
target_link_libraries(coroutine_socket_benchmark PRIVATE eventloop::eventloop)
target_compile_options(coroutine_socket_benchmark PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(coroutine_socket_benchmark PRIVATE -Wno-mismatched-new-delete)
endif()

if(BUILD_TESTING)
    add_executable(http_api_test tests/http_api.cc)
    target_link_libraries(http_api_test PRIVATE eventloop::eventloop OpenSSL::Crypto)
    target_compile_options(http_api_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME http_api COMMAND http_api_test)
    set_tests_properties(http_api PROPERTIES TIMEOUT 10)

    add_executable(coroutine_smoke_test tests/coroutine_smoke.cc)
    target_link_libraries(coroutine_smoke_test PRIVATE eventloop::eventloop)
    target_compile_options(coroutine_smoke_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME coroutine_smoke COMMAND coroutine_smoke_test)

    add_executable(socket_api_test tests/socket_api.cc)
    target_link_libraries(socket_api_test PRIVATE eventloop::eventloop OpenSSL::Crypto)
    target_compile_definitions(socket_api_test PRIVATE EVENTLOOP_TEST_TLS=1)
    target_compile_options(socket_api_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME socket_api COMMAND socket_api_test)
    set_tests_properties(socket_api PROPERTIES TIMEOUT 10)

    find_program(OPENSSL_EXECUTABLE openssl REQUIRED)
    find_program(CURL_EXECUTABLE curl REQUIRED)
    add_executable(tls_openssl_test tests/tls_openssl.cc)
    target_link_libraries(tls_openssl_test PRIVATE eventloop::eventloop OpenSSL::SSL OpenSSL::Crypto)
    target_compile_options(tls_openssl_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME tls_openssl COMMAND tls_openssl_test)
    set_tests_properties(tls_openssl PROPERTIES TIMEOUT 10)

    add_executable(tls_loopback_test tests/tls_loopback.cc)
    target_link_libraries(tls_loopback_test PRIVATE eventloop::eventloop)
    target_compile_options(tls_loopback_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    add_test(
        NAME tls_loopback
        COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_tls_loopback.sh
                     $<TARGET_FILE:tls_loopback_test>
    )
    set_tests_properties(tls_loopback PROPERTIES TIMEOUT 10)

    add_executable(event_loop_test tests/event_loop.cc)
    target_link_libraries(event_loop_test PRIVATE eventloop::eventloop)
    target_compile_options(event_loop_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND
       CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_link_options(event_loop_test PRIVATE -Wl,--wrap=timerfd_settime)
        target_compile_definitions(event_loop_test PRIVATE EVENTLOOP_TEST_WRAP_TIMERFD=1)
    endif()
    add_test(NAME event_loop COMMAND event_loop_test)

    add_executable(http_test tests/http_test.cc)
    target_link_libraries(http_test PRIVATE eventloop::eventloop)
    target_compile_options(http_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME http COMMAND http_test)

    add_executable(http2_hpack_test tests/http2_hpack.cc)
    target_include_directories(http2_hpack_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(http2_hpack_test PRIVATE eventloop::eventloop)
    target_compile_options(http2_hpack_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME http2_hpack COMMAND http2_hpack_test)

    add_executable(quic_varint_test tests/quic_varint.cc)
    target_include_directories(quic_varint_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_varint_test PRIVATE eventloop::eventloop)
    target_compile_options(quic_varint_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_varint COMMAND quic_varint_test)

    add_executable(quic_transport_parameters_test
        tests/quic_transport_parameters.cc)
    target_include_directories(quic_transport_parameters_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_transport_parameters_test PRIVATE
        eventloop::eventloop)
    target_compile_options(quic_transport_parameters_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_transport_parameters
        COMMAND quic_transport_parameters_test)

    add_executable(quic_packet_header_test tests/quic_packet_header.cc)
    target_include_directories(quic_packet_header_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_packet_header_test PRIVATE eventloop::eventloop)
    target_compile_options(quic_packet_header_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_packet_header COMMAND quic_packet_header_test)

    add_executable(quic_frames_test tests/quic_frames.cc)
    target_include_directories(quic_frames_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_frames_test PRIVATE eventloop::eventloop)
    target_compile_options(quic_frames_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_frames COMMAND quic_frames_test)

    add_executable(quic_frame_encoder_test tests/quic_frame_encoder.cc)
    target_include_directories(quic_frame_encoder_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_frame_encoder_test PRIVATE eventloop::eventloop)
    target_compile_options(quic_frame_encoder_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_frame_encoder COMMAND quic_frame_encoder_test)

    add_executable(quic_frame_policy_test tests/quic_frame_policy.cc)
    target_include_directories(quic_frame_policy_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_frame_policy_test PRIVATE
        eventloop::eventloop)
    target_compile_options(quic_frame_policy_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_frame_policy COMMAND quic_frame_policy_test)

    add_executable(quic_crypto_buffer_test tests/quic_crypto_buffer.cc)
    target_include_directories(quic_crypto_buffer_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_crypto_buffer_test PRIVATE
        eventloop::eventloop)
    target_compile_options(quic_crypto_buffer_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_crypto_buffer COMMAND quic_crypto_buffer_test)

    add_executable(quic_crypto_send_buffer_test
        tests/quic_crypto_send_buffer.cc)
    target_include_directories(quic_crypto_send_buffer_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_crypto_send_buffer_test PRIVATE eventloop::eventloop)
    target_compile_options(quic_crypto_send_buffer_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_crypto_send_buffer COMMAND quic_crypto_send_buffer_test)

    add_executable(quic_stream_receive_test tests/quic_stream_receive.cc)
    target_include_directories(quic_stream_receive_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_stream_receive_test PRIVATE eventloop::eventloop)
    target_compile_options(quic_stream_receive_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_stream_receive COMMAND quic_stream_receive_test)

    add_executable(quic_stream_send_buffer_test
        tests/quic_stream_send_buffer.cc)
    target_include_directories(quic_stream_send_buffer_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_stream_send_buffer_test PRIVATE
        eventloop::eventloop)
    target_compile_options(quic_stream_send_buffer_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_stream_send_buffer COMMAND quic_stream_send_buffer_test)

    add_executable(quic_version_negotiation_test
        tests/quic_version_negotiation.cc)
    target_include_directories(quic_version_negotiation_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_version_negotiation_test PRIVATE
        eventloop::eventloop)
    target_compile_options(quic_version_negotiation_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_version_negotiation COMMAND quic_version_negotiation_test)

    add_executable(quic_recovery_timer_test tests/quic_recovery_timer.cc)
    target_include_directories(quic_recovery_timer_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_recovery_timer_test PRIVATE eventloop::eventloop)
    target_compile_options(quic_recovery_timer_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_recovery_timer COMMAND quic_recovery_timer_test)

    add_executable(quic_ack_ranges_test tests/quic_ack_ranges.cc)
    target_include_directories(quic_ack_ranges_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_ack_ranges_test PRIVATE eventloop::eventloop)
    target_compile_options(quic_ack_ranges_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_ack_ranges COMMAND quic_ack_ranges_test)

    add_executable(quic_received_packet_ranges_test
        tests/quic_received_packet_ranges.cc)
    target_include_directories(quic_received_packet_ranges_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_received_packet_ranges_test PRIVATE
        eventloop::eventloop)
    target_compile_options(quic_received_packet_ranges_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_received_packet_ranges
        COMMAND quic_received_packet_ranges_test)

    add_executable(quic_stream_registry_test tests/quic_stream_registry.cc)
    target_include_directories(quic_stream_registry_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_stream_registry_test PRIVATE
        eventloop::eventloop)
    target_compile_options(quic_stream_registry_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_stream_registry COMMAND quic_stream_registry_test)

    add_executable(quic_datagram_queue_test tests/quic_datagram_queue.cc)
    target_include_directories(quic_datagram_queue_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_datagram_queue_test PRIVATE eventloop::eventloop)
    target_compile_options(quic_datagram_queue_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_datagram_queue COMMAND quic_datagram_queue_test)

    add_executable(quic_flow_control_test tests/quic_flow_control.cc)
    target_include_directories(quic_flow_control_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_flow_control_test PRIVATE eventloop::eventloop)
    target_compile_options(quic_flow_control_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_flow_control COMMAND quic_flow_control_test)

    add_executable(quic_path_validation_test tests/quic_path_validation.cc)
    target_include_directories(quic_path_validation_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_path_validation_test PRIVATE eventloop::eventloop)
    target_compile_options(quic_path_validation_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_path_validation COMMAND quic_path_validation_test)

    add_executable(quic_connection_id_registry_test
        tests/quic_connection_id_registry.cc)
    target_include_directories(quic_connection_id_registry_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_connection_id_registry_test PRIVATE
        eventloop::eventloop)
    target_compile_options(quic_connection_id_registry_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_connection_id_registry
        COMMAND quic_connection_id_registry_test)

    add_executable(quic_local_connection_id_registry_test
        tests/quic_local_connection_id_registry.cc)
    target_include_directories(quic_local_connection_id_registry_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_local_connection_id_registry_test PRIVATE
        eventloop::eventloop)
    target_compile_options(quic_local_connection_id_registry_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_local_connection_id_registry
        COMMAND quic_local_connection_id_registry_test)

    add_executable(quic_stream_state_test tests/quic_stream_state.cc)
    target_include_directories(quic_stream_state_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_stream_state_test PRIVATE eventloop::eventloop)
    target_compile_options(quic_stream_state_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_stream_state COMMAND quic_stream_state_test)

    add_executable(quic_connection_lifecycle_test
        tests/quic_connection_lifecycle.cc)
    target_include_directories(quic_connection_lifecycle_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_connection_lifecycle_test PRIVATE
        eventloop::eventloop)
    target_compile_options(quic_connection_lifecycle_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_connection_lifecycle
        COMMAND quic_connection_lifecycle_test)

    add_executable(quic_stateless_reset_test
        tests/quic_stateless_reset.cc)
    target_include_directories(quic_stateless_reset_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_stateless_reset_test PRIVATE
        eventloop::eventloop)
    target_compile_options(quic_stateless_reset_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_stateless_reset COMMAND quic_stateless_reset_test)

    add_executable(quic_ecn_state_test tests/quic_ecn_state.cc)
    target_include_directories(quic_ecn_state_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_ecn_state_test PRIVATE eventloop::eventloop)
    target_compile_options(quic_ecn_state_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_ecn_state COMMAND quic_ecn_state_test)

    add_executable(quic_retry_token_test tests/quic_retry_token.cc)
    target_include_directories(quic_retry_token_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_retry_token_test PRIVATE
        eventloop::eventloop OpenSSL::Crypto)
    target_compile_options(quic_retry_token_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_retry_token COMMAND quic_retry_token_test)

    add_executable(quic_retry_packet_test tests/quic_retry_packet.cc)
    target_include_directories(quic_retry_packet_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_retry_packet_test PRIVATE
        eventloop::eventloop OpenSSL::Crypto)
    target_compile_options(quic_retry_packet_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_retry_packet COMMAND quic_retry_packet_test)

    add_executable(quic_transport_parameter_validation_test
        tests/quic_transport_parameter_validation.cc)
    target_include_directories(quic_transport_parameter_validation_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_transport_parameter_validation_test PRIVATE
        eventloop::eventloop)
    target_compile_options(quic_transport_parameter_validation_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_transport_parameter_validation
        COMMAND quic_transport_parameter_validation_test)

    add_executable(quic_key_update_test tests/quic_key_update.cc)
    target_include_directories(quic_key_update_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_key_update_test PRIVATE
        eventloop::eventloop OpenSSL::Crypto)
    target_compile_options(quic_key_update_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_key_update COMMAND quic_key_update_test)

    add_executable(quic_packet_protection_context_test
        tests/quic_packet_protection_context.cc)
    target_include_directories(quic_packet_protection_context_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_packet_protection_context_test PRIVATE
        eventloop::eventloop OpenSSL::Crypto)
    target_compile_options(quic_packet_protection_context_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_packet_protection_context
        COMMAND quic_packet_protection_context_test)

    add_executable(quic_loss_detection_test tests/quic_loss_detection.cc)
    target_include_directories(quic_loss_detection_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_loss_detection_test PRIVATE eventloop::eventloop)
    target_compile_options(quic_loss_detection_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_loss_detection COMMAND quic_loss_detection_test)

    add_executable(quic_sent_packet_history_test
        tests/quic_sent_packet_history.cc)
    target_include_directories(quic_sent_packet_history_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_sent_packet_history_test PRIVATE
        eventloop::eventloop)
    target_compile_options(quic_sent_packet_history_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_sent_packet_history
        COMMAND quic_sent_packet_history_test)

    add_executable(quic_recovery_orchestration_test
        tests/quic_recovery_orchestration.cc)
    target_include_directories(quic_recovery_orchestration_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_recovery_orchestration_test PRIVATE
        eventloop::eventloop)
    target_compile_options(quic_recovery_orchestration_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_recovery_orchestration
        COMMAND quic_recovery_orchestration_test)

    add_executable(quic_congestion_control_test
        tests/quic_congestion_control.cc)
    target_include_directories(quic_congestion_control_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_congestion_control_test PRIVATE
        eventloop::eventloop)
    target_compile_options(quic_congestion_control_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_congestion_control
        COMMAND quic_congestion_control_test)

    add_executable(quic_path_recovery_state_test
        tests/quic_path_recovery_state.cc)
    target_include_directories(quic_path_recovery_state_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_path_recovery_state_test PRIVATE
        eventloop::eventloop)
    target_compile_options(quic_path_recovery_state_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_path_recovery_state
        COMMAND quic_path_recovery_state_test)

    add_executable(quic_grease_quic_bit_test
        tests/quic_grease_quic_bit.cc)
    target_include_directories(quic_grease_quic_bit_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_grease_quic_bit_test PRIVATE
        eventloop::eventloop OpenSSL::Crypto)
    target_compile_options(quic_grease_quic_bit_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_grease_quic_bit
        COMMAND quic_grease_quic_bit_test)

    add_executable(quic_public_api_test tests/quic_public_api.cc)
    target_include_directories(quic_public_api_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_public_api_test PRIVATE
        eventloop::eventloop OpenSSL::SSL OpenSSL::Crypto)
    target_compile_options(quic_public_api_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(quic_public_api_test PRIVATE
            -Wno-mismatched-new-delete)
    endif()
    add_test(NAME quic_public_api COMMAND quic_public_api_test)
    set_tests_properties(quic_public_api PROPERTIES TIMEOUT 20)

    add_executable(quic_packet_protection_test
        tests/quic_packet_protection.cc)
    target_include_directories(quic_packet_protection_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_packet_protection_test PRIVATE
        eventloop::eventloop)
    target_compile_options(quic_packet_protection_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_packet_protection
        COMMAND quic_packet_protection_test)

    add_executable(quic_protected_packet_test
        tests/quic_protected_packet.cc)
    target_include_directories(quic_protected_packet_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_protected_packet_test PRIVATE
        eventloop::eventloop)
    target_compile_options(quic_protected_packet_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_protected_packet
        COMMAND quic_protected_packet_test)

    add_executable(quic_tls_test tests/quic_tls.cc)
    target_include_directories(quic_tls_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_tls_test PRIVATE
        eventloop::eventloop OpenSSL::SSL OpenSSL::Crypto)
    target_compile_options(quic_tls_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_tls COMMAND quic_tls_test)

    add_executable(quic_connection_core_test
        tests/quic_connection_core.cc)
    target_include_directories(quic_connection_core_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_connection_core_test PRIVATE
        eventloop::eventloop OpenSSL::SSL OpenSSL::Crypto)
    target_compile_options(quic_connection_core_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_connection_core COMMAND quic_connection_core_test)

    add_executable(quic_connection_test tests/quic_connection.cc)
    target_include_directories(quic_connection_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_connection_test PRIVATE
        eventloop::eventloop OpenSSL::SSL OpenSSL::Crypto)
    target_compile_options(quic_connection_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_connection COMMAND quic_connection_test)

    add_executable(quic_packet_scheduler_test tests/quic_packet_scheduler.cc)
    target_include_directories(quic_packet_scheduler_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_packet_scheduler_test PRIVATE
        eventloop::eventloop OpenSSL::SSL OpenSSL::Crypto)
    target_compile_options(quic_packet_scheduler_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_packet_scheduler COMMAND quic_packet_scheduler_test)

    add_executable(quic_endpoint_router_test tests/quic_endpoint_router.cc)
    target_include_directories(quic_endpoint_router_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_endpoint_router_test PRIVATE eventloop::eventloop)
    target_compile_options(quic_endpoint_router_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_endpoint_router COMMAND quic_endpoint_router_test)

    add_executable(quic_connection_driver_test tests/quic_connection_driver.cc)
    target_include_directories(quic_connection_driver_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_connection_driver_test PRIVATE eventloop::eventloop OpenSSL::SSL OpenSSL::Crypto)
    add_test(NAME quic_connection_driver COMMAND quic_connection_driver_test)
    set_tests_properties(quic_connection_driver PROPERTIES TIMEOUT 15)

    add_executable(quic_driver_failure_test tests/quic_driver_failure.cc)
    target_link_libraries(quic_driver_failure_test PRIVATE
        eventloop::eventloop OpenSSL::SSL OpenSSL::Crypto)
    target_compile_options(quic_driver_failure_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_driver_failure COMMAND quic_driver_failure_test)
    set_tests_properties(quic_driver_failure PROPERTIES TIMEOUT 15)

    add_executable(http3_frames_test tests/http3_frames.cc)
    target_include_directories(http3_frames_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(http3_frames_test PRIVATE eventloop::eventloop)
    target_compile_options(http3_frames_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME http3_frames COMMAND http3_frames_test)

    add_executable(http3_qpack_test tests/http3_qpack.cc src/http3/qpack.cc)
    target_include_directories(http3_qpack_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(http3_qpack_test PRIVATE eventloop::eventloop)
    target_compile_options(http3_qpack_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME http3_qpack COMMAND http3_qpack_test)

    add_executable(quic_udp_endpoint_test tests/quic_udp_endpoint.cc)
    target_include_directories(quic_udp_endpoint_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(quic_udp_endpoint_test PRIVATE
        eventloop::eventloop OpenSSL::Crypto)
    target_compile_options(quic_udp_endpoint_test PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME quic_udp_endpoint COMMAND quic_udp_endpoint_test)

    add_executable(executor_test tests/executor.cc)
    target_include_directories(executor_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(executor_test PRIVATE eventloop::eventloop)
    target_compile_options(executor_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME executor COMMAND executor_test)
    set_tests_properties(executor PROPERTIES TIMEOUT 30)

    add_executable(web_socket_test tests/web_socket.cc)
    target_link_libraries(web_socket_test PRIVATE eventloop::eventloop)
    target_compile_options(web_socket_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    add_test(NAME web_socket COMMAND web_socket_test)

    add_executable(task_test tests/task.cc)
    target_link_libraries(task_test PRIVATE eventloop::eventloop)
    target_compile_options(task_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        # GCC diagnoses the standard coroutine allocation/deallocation pair as
        # mismatched when allocation receives coroutine function arguments.
        target_compile_options(task_test PRIVATE -Wno-mismatched-new-delete)
    endif()
    add_test(NAME task COMMAND task_test)

    add_executable(task_composition_test tests/task_composition.cc)
    target_link_libraries(task_composition_test PRIVATE eventloop::eventloop)
    target_compile_options(task_composition_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(task_composition_test PRIVATE -Wno-mismatched-new-delete)
    endif()
    add_test(NAME task_composition COMMAND task_composition_test)

    add_executable(task_handle_test tests/task_handle.cc)
    target_link_libraries(task_handle_test PRIVATE eventloop::eventloop)
    target_compile_options(task_handle_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(task_handle_test PRIVATE -Wno-mismatched-new-delete)
    endif()
    add_test(NAME task_handle COMMAND task_handle_test)

    add_executable(file_io_test tests/file_io.cc)
    target_link_libraries(file_io_test PRIVATE eventloop::eventloop)
    target_compile_options(file_io_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(file_io_test PRIVATE -Wno-mismatched-new-delete)
    endif()
    add_test(NAME file_io COMMAND file_io_test)
    set_tests_properties(file_io PROPERTIES TIMEOUT 10)

    add_executable(coroutine_tcp_test tests/tcp_coroutine.cc)
    target_link_libraries(coroutine_tcp_test PRIVATE eventloop::eventloop)
    target_compile_options(coroutine_tcp_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(coroutine_tcp_test PRIVATE -Wno-mismatched-new-delete)
    endif()
    add_test(NAME coroutine_tcp COMMAND coroutine_tcp_test)
    set_tests_properties(coroutine_tcp PROPERTIES TIMEOUT 10)

    add_executable(coroutine_udp_test tests/udp_coroutine.cc)
    target_link_libraries(coroutine_udp_test PRIVATE eventloop::eventloop)
    target_compile_options(coroutine_udp_test PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(coroutine_udp_test PRIVATE -Wno-mismatched-new-delete)
    endif()
    add_test(NAME coroutine_udp COMMAND coroutine_udp_test)
    set_tests_properties(coroutine_udp PROPERTIES TIMEOUT 10)

    add_test(
        NAME http_server
        COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_http_server.sh
                     $<TARGET_FILE:http_server>
                     ${OPENSSL_EXECUTABLE}
                     ${CURL_EXECUTABLE}
    )
    set_tests_properties(http_server PROPERTIES TIMEOUT 15)
    option(EVENTLOOP_WEBSOCKET_INTEROP_TESTS
        "Enable Python websockets interoperability test" OFF)
    if(EVENTLOOP_WEBSOCKET_INTEROP_TESTS)
        find_package(Python3 REQUIRED COMPONENTS Interpreter)
        execute_process(COMMAND "${Python3_EXECUTABLE}" -c "import websockets"
            RESULT_VARIABLE websocket_python_result)
        if(NOT websocket_python_result EQUAL 0)
            message(FATAL_ERROR "WebSocket interop test requires Python websockets")
        endif()
        add_test(NAME websocket_server_interop
            COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_websocket_server.py"
                $<TARGET_FILE:websocket_echo_server>)
        set_tests_properties(websocket_server_interop PROPERTIES TIMEOUT 20)
    endif()

    add_test(
        NAME http2_server
        COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_http2_server.sh
                     $<TARGET_FILE:http_server>
                     ${OPENSSL_EXECUTABLE}
                     ${CURL_EXECUTABLE}
    )
    set_tests_properties(http2_server PROPERTIES TIMEOUT 30)

    add_test(
        NAME http3_server
        COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_http3_server.sh
                     $<TARGET_FILE:http3_file_server>
                     ${OPENSSL_EXECUTABLE}
                     ${CURL_EXECUTABLE}
    )
    set_tests_properties(http3_server PROPERTIES TIMEOUT 30)
endif()

eventloop_register_http3_interop_tests()
