.PHONY: zip

MKDIR := mkdir
ZIP := zip

zip:
	$(MKDIR) -p zip
	$(ZIP) zip/conformity-custom-check.zip handler.py

create-function: zip
	aws lambda create-function --function-name $(FUNCTION_NAME) \
	--role $(ROLE_ARN) --runtime python3.8 \
	--timeout 300 --memory-size 256 --handler handler.lambda_handler \
	--environment Variables=\{CC_REGION=${CC_REGION},CC_APIKEY=${CC_APIKEY},CC_CUSTOMCHECKID=${CC_CUSTOMCHECKID},CC_CHECKSEV=${CC_CHECKSEV},FSS_APIKEY=$(FSS_APIKEY)\} \
	--zip-file fileb://zip/conformity-custom-check.zip
