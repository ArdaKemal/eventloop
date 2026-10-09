#pragma once

#include <filesystem>
#include <memory>
#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

namespace eventloop::test {
inline auto make_localhost_certificate(const std::filesystem::path& certificate_path,
                                       const std::filesystem::path& key_path) -> void
{
    auto check = [](bool ok) {
        if (!ok) throw std::runtime_error("generate TLS test certificate");
    };
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key {
        EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", 2048), EVP_PKEY_free};
    std::unique_ptr<X509, decltype(&X509_free)> certificate {X509_new(), X509_free};
    check(key && certificate);
    auto* cert = certificate.get();
    check(X509_set_version(cert, 2) == 1);
    check(ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) == 1);
    check(ASN1_TIME_set_string(X509_getm_notBefore(cert), "20260101000000Z") == 1);
    check(ASN1_TIME_set_string(X509_getm_notAfter(cert), "20300101000000Z") == 1);
    check(X509_set_pubkey(cert, key.get()) == 1);
    std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)> subject {
        X509_NAME_new(), X509_NAME_free};
    check(subject != nullptr);
    check(X509_NAME_add_entry_by_txt(subject.get(), "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0) == 1);
    check(X509_set_subject_name(cert, subject.get()) == 1);
    check(X509_set_issuer_name(cert, subject.get()) == 1);
    std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> san {
        X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name,
                          const_cast<char*>("DNS:localhost")), X509_EXTENSION_free};
    check(san && X509_add_ext(cert, san.get(), -1) == 1);
    check(X509_sign(cert, key.get(), EVP_sha256()) > 0);
    // Write directly to file BIOs; no intermediate PEM strings or memory BIOs.
    std::unique_ptr<BIO, decltype(&BIO_free)> cert_file {
        BIO_new_file(certificate_path.string().c_str(), "wb"), BIO_free};
    std::unique_ptr<BIO, decltype(&BIO_free)> key_file {
        BIO_new_file(key_path.string().c_str(), "wb"), BIO_free};
    check(cert_file && key_file);
    check(PEM_write_bio_X509(cert_file.get(), cert) == 1);
    check(PEM_write_bio_PrivateKey(key_file.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) == 1);
    check(BIO_flush(cert_file.get()) == 1 && BIO_flush(key_file.get()) == 1);
}
} // namespace eventloop::test
