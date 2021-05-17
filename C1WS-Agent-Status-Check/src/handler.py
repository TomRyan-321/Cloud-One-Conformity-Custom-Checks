import boto3
import copy
import json
import os
import urllib3

ccregion = os.environ.get("CC_REGION", "us-west-2")
secretsarn = os.environ["SECRETS_ARN"]
customcheckid = os.environ.get("CC_CUSTOMCHECKID", "CUSTOM-100").upper()
customchecksev = os.environ.get("CC_CHECKSEV", "MEDIUM").upper()
regexfilter = os.environ.get("REGEX_FILTER", None)

http = urllib3.PoolManager()

secrets = boto3.client("secretsmanager").get_secret_value(SecretId=secretsarn)
secrets_data = json.loads(secrets["SecretString"])
ccapikey = secrets_data["ccapikey"]
wsapikey = secrets_data["wsapikey"]

conformityheaders = {
    "Content-Type": "application/vnd.api+json",
    "Authorization": "ApiKey " + ccapikey,
}


def get_all_confromity_accountids():
    accountsapi = f"https://{ccregion}-api.cloudconformity.com/v1/accounts"
    r = http.request("GET", accountsapi, headers=conformityheaders)
    return json.loads(r.data.decode("utf-8"))["data"]


def match_aws_to_conformity_accid(awsaccountid):
    for account in all_conformity_accounts:
        try:
            if account["attributes"]["awsaccount-id"] == awsaccountid:
                return account["id"]
        except:
            pass


def get_all_workload_computers():
    wsheaders = {
        "api-version": "v1",
        "api-secret-key": wsapikey,
        "Content-Type": "application/json",
    }
    wscomputersapi = "https://cloudone.trendmicro.com/api/computers?expand=ec2VirtualMachineSummary&expand=computerStatus"
    r = http.request("GET", wscomputersapi, headers=wsheaders)
    return json.loads(r.data.decode("utf-8"))["computers"]


all_conformity_accounts = get_all_confromity_accountids()


def lambda_handler(event, context):
    findings = []
    for computer in get_all_workload_computers():
        try:
            agentstatus = computer["computerStatus"]["agentStatus"]
            agentstatusmsg = computer["computerStatus"]["agentStatusMessages"][0]
            awsaccountid = computer["ec2VirtualMachineSummary"]["accountID"]
            ccaccountid = match_aws_to_conformity_accid(awsaccountid)
            instanceid = computer["ec2VirtualMachineSummary"]["instanceID"]
            instancetype = computer["ec2VirtualMachineSummary"]["type"]
            instancestate = computer["ec2VirtualMachineSummary"]["state"]
            instanceaz = computer["ec2VirtualMachineSummary"]["availabilityZone"]
            instanceregion = instanceaz[:-1]
            instanceami = computer["ec2VirtualMachineSummary"]["amiID"]
            instanceplatform = computer["platform"]
            instancetags = []
            for tag in computer["ec2VirtualMachineSummary"]["metadata"]:
                try:
                    instancetags.append(f"{tag['name']}::{tag['value']}")
                except:
                    pass
            checkstatus = "FAILURE" if agentstatus != "active" else "SUCCESS"
            message = f"Workload Security agent status is {agentstatus} on Instance ID: {instanceid} with status message of: {agentstatusmsg}"
            finding = {
                "type": "checks",
                "attributes": {
                    "rule-title": "C1 Workload Security Agent Status",
                    "message": message,
                    "not-scored": False,
                    "region": instanceregion,
                    "resource": instanceid,
                    "risk-level": customchecksev,
                    "status": checkstatus,
                    "service": "EC2",
                    "categories": ["security"],
                    "resolution-page-url": "https://cloudone.trendmicro.com/docs/workload-security/agent-status/",
                    # "tags": instancetags, ## Removed this due to out of date limitations on conformity custom api endpoint limiting tags to a maximum of 20 tagsand total key:value length to 50 characters.
                    "extradata": [
                        {
                            "label": "Instance AMI",
                            "name": "Instance AMI",
                            "type": "Meta",
                            "value": instanceami,
                        },
                        {
                            "label": "Instance Type",
                            "name": "Instance Type",
                            "type": "Meta",
                            "value": instancetype,
                        },
                        {
                            "label": "Instance Platform",
                            "name": "Instance Platform",
                            "type": "Meta",
                            "value": instanceplatform,
                        },
                        {
                            "label": "Instance State",
                            "name": "Instance State",
                            "type": "Meta",
                            "value": instancestate,
                        },
                        {
                            "label": "C1WS Console",
                            "name": "C1WS Console",
                            "type": "Meta",
                            "value": "https://cloudone.trendmicro.com/workload#computers_root",
                        },
                        {
                            "label": "C1WS Agent KB",
                            "name": "C1WS Agent KB",
                            "type": "Meta",
                            "value": "https://cloudone.trendmicro.com/docs/workload-security/agent-status/",
                        },
                        {
                            "label": "AWS EC2 Console",
                            "name": "AWS EC2 Console",
                            "type": "Meta",
                            "value": f"https://console.aws.amazon.com/ec2/v2/home?region={instanceregion}#InstanceDetails:instanceId={instanceid}",
                        },
                        {
                            "label": "Check ID",
                            "name": "Check ID",
                            "type": "Meta",
                            "value": customcheckid,
                        },
                    ],
                },
                "relationships": {
                    "account": {"data": {"id": ccaccountid, "type": "accounts"}},
                    "rule": {"data": {"id": customcheckid, "type": "rules"}},
                },
            }
            findings.append(copy.deepcopy(finding))
        except:
            pass

    bodyencoded = json.dumps({"data": findings}).encode("utf-8")
    checksapi = f"https://{ccregion}-api.cloudconformity.com/v1/checks"

    r = http.request("POST", checksapi, body=bodyencoded, headers=conformityheaders)
    print(r.data.decode("utf-8"))


if __name__ == "__main__":
    lambda_handler("event", "context")
