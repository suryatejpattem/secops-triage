from pathlib import Path

from secops_triage.models import IndicatorType
from secops_triage.parsers import zeek

FIXTURES = Path(__file__).parent / "fixtures"


def test_read_ndjson_yields_records_and_counts_what_it_skips():
    stats = zeek.ReadStats()
    records = list(zeek.read_ndjson(FIXTURES / "conn.log", stats))
    assert len(records) == 5  # 7 lines: one is not JSON, one is a JSON list
    assert stats.lines == 7
    assert stats.skipped == 2


def test_read_ndjson_survives_bytes_that_are_not_utf8(tmp_path):
    p = tmp_path / "dns.log"
    p.write_bytes(b'{"query": "caf\xe9.example"}\n')  # Latin-1 byte, invalid as UTF-8
    [rec] = zeek.read_ndjson(p)
    assert rec["query"].startswith("caf")


def test_conn_extracts_destination_ips_with_the_right_type():
    found = {(i.value, i.type) for i in zeek.extract_from_conn(FIXTURES / "conn.log")}
    assert found == {
        ("93.184.216.34", IndicatorType.IPV4),
        ("192.0.2.10", IndicatorType.IPV4),
        ("2001:db8::1", IndicatorType.IPV6),
    }


def test_conn_keeps_port_and_service_as_context():
    first = next(zeek.extract_from_conn(FIXTURES / "conn.log"))
    assert first.context == {"port": "443", "service": "ssl"}


def test_conn_records_without_a_service_say_unknown():
    scan = [
        i
        for i in zeek.extract_from_conn(FIXTURES / "conn.log")
        if i.value == "192.0.2.10"
    ]
    assert all(i.context["service"] == "unknown" for i in scan)


def test_dns_normalises_case_and_trailing_dot():
    names = [i.value for i in zeek.extract_from_dns(FIXTURES / "dns.log")]
    assert names == ["example.com", "example.com"]


def test_dns_skips_records_without_a_usable_query():
    # one record has no query, one has a number where a name should be
    assert len(list(zeek.extract_from_dns(FIXTURES / "dns.log"))) == 2


def test_ssl_extracts_sni_and_skips_nulls():
    names = {i.value for i in zeek.extract_from_ssl(FIXTURES / "ssl.log")}
    assert names == {"example.org", "api.example.net"}


def test_parsers_are_lazy():
    """Parsers must return generators, not lists: memory matters on real logs."""
    result = zeek.extract_from_conn(FIXTURES / "conn.log")
    assert not isinstance(result, list)
    assert hasattr(result, "__next__")
