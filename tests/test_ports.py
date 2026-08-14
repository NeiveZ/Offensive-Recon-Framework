from modules.port_scanner import PortScanner


def test_port_parser():
    scanner = PortScanner()
    assert scanner._parse_ports("80,443,8000-8002") == [80,443,8000,8001,8002]
    assert all(1 <= p <= 65535 for p in scanner._parse_ports("1-65535"))
