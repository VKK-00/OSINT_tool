from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from uvb76_collect import infer_page_period, parse_html_page, parse_message_blocks


FIXTURE = """
<!doctype html><html><head><title>January 2024 › The Buzzer › Priyom.org</title></head>
<body><table><thead><tr>
<th>Date</th><th>Time</th><th>Frequency</th><th>Callsign</th><th>Group</th>
<th>Message</th><th>Russian</th><th>Remarks</th></tr></thead><tbody>
<tr>
<td>January 18, 2024</td><td>11:28</td>
<td><ul><li>4625 kHz H3E (USB)</li></ul></td>
<td>NZhTI/НЖТИ</td><td>42493</td>
<td><p class="messageCol">ROKOShTOF 6856 1920 LIMBODUH 3641 5048</p></td>
<td><p class="messageCol">РОКОШТОФ 6856 1920 ЛИМБОДУХ 3641 5048</p></td>
<td><p>Repeated:</p><p>22.07.2021 (09:15) NZhTI 76049 LIMBODUH 3641 5048</p></td>
</tr>
</tbody></table></body></html>
"""


def test_parse_page_preserves_source_fields_and_extracts_two_blocks():
    page, transmissions, blocks, repeats, issues = parse_html_page(
        FIXTURE,
        source_url="https://priyom.org/military-stations/russia/the-buzzer/2024/january",
        retrieved_at="2026-09-04T00:00:00Z",
    )
    assert page["page_year"] == 2024
    assert page["page_month"] == 1
    assert len(transmissions) == 1
    row = transmissions[0]
    assert row["date"] == "2024-01-18"
    assert row["time_local_text"] == "11:28"
    assert row["time_zone"] == "UTC"
    assert row["frequency_khz"] == "4625"
    assert row["callsign_raw"] == "NZhTI/НЖТИ"
    assert row["key_group_raw"] == "42493"
    assert len(blocks) == 2
    assert [b["payload_normalized"] for b in blocks] == ["68561920", "36415048"]
    assert [b["codeword_latin"] for b in blocks] == ["ROKOShTOF", "LIMBODUH"]
    assert repeats and repeats[0]["ref_payload"] == "36415048"
    assert not issues


def test_uncertain_payload_is_preserved_but_not_silently_corrected():
    blocks = parse_message_blocks("BUKSOPSIH ????????", transmission_id="x")
    assert len(blocks) == 1
    assert blocks[0]["payload_raw"] == "????????"
    assert blocks[0]["payload_normalized"] == "????????"
    assert blocks[0]["payload_quality"] == "uncertain"


def test_page_period_is_inferred_from_title_and_url():
    assert infer_page_period(
        "January 2024 › The Buzzer › Priyom.org",
        "https://priyom.org/military-stations/russia/the-buzzer/2024/january",
    ) == (2024, 1)
    assert infer_page_period(
        "2011 › The Buzzer › Priyom.org",
        "https://priyom.org/military-stations/russia/the-buzzer/2011",
    ) == (2011, None)
