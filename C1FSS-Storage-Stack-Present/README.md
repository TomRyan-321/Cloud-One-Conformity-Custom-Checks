# Cloud One Conformity Custom Check - File Storage Security Stack deployed for bucket.

Once an hour get a list of all buckets within an AWS account and check if they have Trend Micro's Cloud One File Storage Security stack deployed to scan new objects for malware. The solution supports regular expression passed through as an environment variable to filter out buckets. Example: To exclude any buckets with name suffix of `-promote` or `-quarantine` use the default regex filter of: `.*-quarantine|.*-promote`

## Prerequisites
1. **Install AWS SAM CLI**
    - Visit [Installing the AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html) for detailed instructions for your Operating System.
    - Configure your [AWS Credentials](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-getting-started-set-up-credentials.html) for use with AWS SAM CLI.
2. **Configure Conformity API Key**
    - Log into **Conformity** and select your username and select `User settings`.
    - Select `API Keys`.
    - Select `+ New API Key`, then select `Generate Key`.
    - Copy the generated API Key for use later when installing the function.
3. **Configure File Storage API Key**
    - Log into **Workload Security** and select `Administration`.
    - Expand `User Management` and select `API Keys`.
    - Select `New`, give your key a name and then select **Role** and select `Auditor` access. 
    - Select `Next` and copy the generated API key for use later when installing the function.

## Installation

### From AWS SAM CLI

1. Clone this repository from [Github](https://github.com/TomRyan-321/Cloud-One-Conformity-Custom-Checks).
2. Using your terminal navigate to the `C1FSS-Storage-Stack-Present` folder contained within the above cloned repository. Example: `User@Host:cd ~/cloud-One-Conformity-Custom-Checks/C1FSS-Storage-Stack-Present`
3. Deploy the SAM template in guided mode. Example: `sam deploy --guided`
4. Fill in the required parameters as promoted. Defaults are provided for all values with the exception of FSS & Conformity API keys which were obtained in prerequiste steps.
5. Select `Yes` by press `Y` to the following prompts: `Confirm changes before deploy`, `Allow SAM CLI IAM role creation`
6. Optionally save the above parameters to a configuration file when promtped (note API keys will **NOT** be written to this file and always need to be re-entered if redeploying)
7. Review the resources to be created/updated and select `Yes` by press `y` to deploy the solution.

## Test the Application

The solution will automatically run one hour after successful deployment. Results will automatically appear with Conformity post a successful. Alternative follow the steps below to force a manual execution of the function.

**Manually trigger function**
- Navigate to the **Lambda > Functions** service console.
- Find and select the function deployed by the SAM template. Example: `sam-app-FSSDeployedConformityChecksFunction-<UniqueIdentifier>`
- Select `Test` tab then select `Invoke`. (Leave test event template as the default hello-world values as these are not parsed by the function)
- Expand `Execution results` on completion and confirm result was `succeeded`. (If failed view the logs in **CloudWatch Logs** to determine any errors)
- Within **Conformity** select **Browse All Checks** and search for the findings which have been uploaded to your Account. (Quickly filter results by using the filter **Filter by resource Id, rule title or message** with a value of `C1 File Storage Security Enabled for Bucket`).
- Review the results.