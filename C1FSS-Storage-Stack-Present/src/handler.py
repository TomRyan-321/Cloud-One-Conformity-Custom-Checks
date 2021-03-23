import boto3
import json
import os
import re
import urllib3

ccregion = os.environ.get("CC_REGION", "us-west-2")
secretsarn = os.environ["SECRETS_ARN"]
customcheckid = os.environ.get("CC_CUSTOMCHECKID", "CUSTOM-002").upper()
customchecksev = os.environ.get("CC_CHECKSEV", "MEDIUM").upper()
regexfilter = os.environ.get("REGEX_FILTER", None)

http = urllib3.PoolManager()

secrets = boto3.client("secretsmanager").get_secret_value(SecretId=secretsarn)
secrets_data = json.loads(secrets["SecretString"])
ccapikey = secrets_data["ccapikey"]
fssapikey = secrets_data["fssapikey"]

conformityheaders = {
    "Content-Type": "application/vnd.api+json",
    "Authorization": "ApiKey " + ccapikey,
}


def get_cc_accountid(awsaccountid):
    accountsapi = f"https://{ccregion}-api.cloudconformity.com/v1/accounts"
    r = http.request("GET", accountsapi, headers=conformityheaders)
    accounts = json.loads(r.data.decode("utf-8"))["data"]
    for account in accounts:
        if account["attributes"]["awsaccount-id"] == awsaccountid:
            return account["id"]


def get_s3_buckets():
    s3 = boto3.client("s3")
    response = s3.list_buckets()
    s3buckets = []
    for bucket in response["Buckets"]:
        s3buckets.append(bucket["Name"])
    return s3buckets


def get_fss_stacks():
    fssstacksapi = "https://cloudone.trendmicro.com/api/filestorage/stacks"
    fssheaders = {
        "Content-Type": "application/json",
        "Api-Version": "v1",
        "api-secret-key": fssapikey,
    }

    r = http.request("GET", fssstacksapi, headers=fssheaders)
    fss_stacks = json.loads(r.data.decode("utf-8"))["stacks"]
    storagestacks = []
    for stack in fss_stacks:
        stacktype = stack["type"]
        if stacktype == "storage":
            storagestacks.append(stack["storage"])
    return storagestacks


def lambda_handler(event, context):
    awsaccountid = boto3.client("sts").get_caller_identity()["Account"]
    ccaccountid = get_cc_accountid(awsaccountid)
    s3buckets = get_s3_buckets()
    fss_stacks = get_fss_stacks()

    for bucket in s3buckets:
        if regexfilter and re.search(regexfilter, bucket):
            status = "SUCCESS"
            message = fr"C1 File Storage Security is exempted for bucket: {bucket} using regex filter: {regexfilter}"
        elif bucket in fss_stacks:
            status = "SUCCESS"
            message = f"C1 File Storage Security is enabled for bucket: {bucket}"
        else:
            status = "FAILURE"
            message = f"C1 File Storage Security is not enabled for bucket: {bucket}"

        s3arn = "arn:aws:s3:::" + bucket
        s3consoleurl = "https://s3.console.aws.amazon.com/s3/buckets/" + bucket
        checksdata = {
            "data": [
                {
                    "type": "checks",
                    "attributes": {
                        "rule-title": "C1 File Storage Security Enabled for Bucket",
                        "message": message,
                        "not-scored": False,
                        "region": "global",
                        "resource": bucket,
                        "risk-level": customchecksev,
                        "status": status,
                        "service": "S3",
                        "categories": ["security"],
                        "link": "https://cloudone.trendmicro.com/filestorage/deployment",
                        "extradata": [
                            {
                                "label": "S3 ARN",
                                "name": "S3 ARN",
                                "type": "Meta",
                                "value": s3arn,
                            },
                            {
                                "label": "S3 Console URL",
                                "name": "S3 Console URL",
                                "type": "Meta",
                                "value": s3consoleurl,
                            },
                        ],
                    },
                    "relationships": {
                        "account": {"data": {"id": ccaccountid, "type": "accounts"}},
                        "rule": {"data": {"id": customcheckid, "type": "rules"}},
                    },
                }
            ]
        }

        bodyencoded = json.dumps(checksdata).encode("utf-8")
        checksapi = f"https://{ccregion}-api.cloudconformity.com/v1/checks"

        r = http.request("POST", checksapi, body=bodyencoded, headers=conformityheaders)
        print(r.data.decode("utf-8"))
