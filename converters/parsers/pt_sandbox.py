import json
import logging

from converters.models import Finding

from cvss import CVSS3

LOGGER = logging.getLogger(__name__)


def _get_cvssv3(cvss_dict: dict):
    """Extracts and returns a CVSS3 object from a CVSS dictionary.
    This function sorts the dictionary by the V3Score value in descending order and searches for elements
    that match the priority keys. If an element with a V3Score is found, it is returned as a tuple
    containing the CVSS vector and the V3Score value."""
    return None, None


def _get_cwes_id(cwes: list):
    # return [int(cwe.split("-")[1]) for cwe in cwes]
    return []


def _fix_severity(severity):
    return "Critical"


class PTSandboxJSONParser:
    def _get_findings_json(self, file, test):
        """Load a PTSandbox file in JSON format"""
        data = json.load(file)
        result = data.get("data", {}).get("result", {}).get("verdict", None) if data.get("data") else None

        if not result or not result == "DANGEROUS":
            return

        findings = []

        finding = Finding(
            title="Found Bad File",
            test=test,
            description=json.dumps(data, indent=2),
            severity="Critical",
            mitigation="",  # todo add if necessary
            component_name="bad file",
            component_version="0.0.1",
            references=[],
            static_finding=False,
            dynamic_finding=False,
            vuln_id_from_tool="1234567890",
            cvss3_vector=None,
            cvss3_score=None
        )

        findings.append(finding)
        return findings


class PTSandboxParser:
    def get_scan_types(self):
        return ["PTSandbox Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "PTSandbox Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Support PTSandbox JSON report formats."

    def get_findings(self, file, test):
        if file.name.strip().lower().endswith(".json"):
            return PTSandboxJSONParser()._get_findings_json(file, test)
