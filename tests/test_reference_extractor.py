from threatweaver.graph.reference_extractor import extract_references


def test_extract_reference_from_string() -> None:
    value = "aws_subnet.public.id"

    assert extract_references(value) == {"aws_subnet.public"}


def test_extract_reference_from_interpolation() -> None:
    value = "${aws_security_group.web.id}"

    assert extract_references(value) == {"aws_security_group.web"}


def test_extract_references_from_nested_attributes() -> None:
    value = {
        "subnet_id": "aws_subnet.public.id",
        "security_groups": [
            "aws_security_group.web.id",
            "aws_security_group.internal.id",
        ],
    }

    assert extract_references(value) == {
        "aws_subnet.public",
        "aws_security_group.web",
        "aws_security_group.internal",
    }


def test_ignore_plain_strings() -> None:
    value = {
        "name": "web-server",
        "environment": "production",
    }

    assert extract_references(value) == set()
