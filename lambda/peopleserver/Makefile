.PHONY: build clean deploy local test

# Build settings
GOOS ?= linux
GOARCH ?= arm64
CGO_ENABLED ?= 0

# SAM settings
STACK_NAME ?= peopleserver
ENVIRONMENT ?= dev
REGION ?= us-east-1

# Build the Lambda function binary
build:
	@echo "Building Lambda function..."
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO_ENABLED) go build -tags lambda.norpc -o bootstrap main.go
	@echo "Build complete: bootstrap"

# Clean build artifacts
clean:
	rm -f bootstrap
	rm -rf .aws-sam

# Deploy to AWS using SAM
deploy: build
	@echo "Deploying to AWS..."
	sam deploy \
		--stack-name $(STACK_NAME)-$(ENVIRONMENT) \
		--template-file template.yaml \
		--capabilities CAPABILITY_IAM \
		--region $(REGION) \
		--parameter-overrides Environment=$(ENVIRONMENT) \
		--resolve-s3 \
		--no-confirm-changeset
	@echo "Deployment complete!"

# Deploy with custom domain
deploy-domain: build
	@if [ -z "$(DOMAIN_NAME)" ]; then echo "Error: DOMAIN_NAME is required"; exit 1; fi
	@if [ -z "$(CERTIFICATE_ARN)" ]; then echo "Error: CERTIFICATE_ARN is required"; exit 1; fi
	@echo "Deploying to AWS with custom domain $(DOMAIN_NAME)..."
	sam deploy \
		--stack-name $(STACK_NAME)-$(ENVIRONMENT) \
		--template-file template.yaml \
		--capabilities CAPABILITY_IAM \
		--region $(REGION) \
		--parameter-overrides \
			Environment=$(ENVIRONMENT) \
			DomainName=$(DOMAIN_NAME) \
			CertificateArn=$(CERTIFICATE_ARN) \
		--resolve-s3 \
		--no-confirm-changeset
	@echo "Deployment complete!"

# Run locally using SAM Local
local: build
	@echo "Starting local API Gateway..."
	sam local start-api \
		--template-file template.yaml \
		--parameter-overrides Environment=local \
		--env-vars env.json \
		--port 8888

# Invoke function locally
invoke: build
	sam local invoke PeopleServerFunction \
		--template-file template.yaml \
		--event events/authorize.json \
		--env-vars env.json

# Run tests
test:
	go test -v ./...

# View logs
logs:
	sam logs -n PeopleServerFunction \
		--stack-name $(STACK_NAME)-$(ENVIRONMENT) \
		--region $(REGION) \
		--tail

# Delete the stack
delete:
	@echo "Deleting stack $(STACK_NAME)-$(ENVIRONMENT)..."
	sam delete \
		--stack-name $(STACK_NAME)-$(ENVIRONMENT) \
		--region $(REGION) \
		--no-prompts
	@echo "Stack deleted!"

# Show outputs
outputs:
	aws cloudformation describe-stacks \
		--stack-name $(STACK_NAME)-$(ENVIRONMENT) \
		--region $(REGION) \
		--query 'Stacks[0].Outputs' \
		--output table

# Help
help:
	@echo "PeopleServer Lambda Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make build          - Build the Lambda binary"
	@echo "  make clean          - Remove build artifacts"
	@echo "  make deploy         - Deploy to AWS"
	@echo "  make deploy-domain  - Deploy with custom domain (requires DOMAIN_NAME and CERTIFICATE_ARN)"
	@echo "  make local          - Run locally with SAM"
	@echo "  make invoke         - Invoke function locally with test event"
	@echo "  make logs           - Tail Lambda logs"
	@echo "  make delete         - Delete the AWS stack"
	@echo "  make outputs        - Show stack outputs"
	@echo ""
	@echo "Environment Variables:"
	@echo "  ENVIRONMENT    - Deployment environment (default: dev)"
	@echo "  REGION         - AWS region (default: us-east-1)"
	@echo "  STACK_NAME     - CloudFormation stack name (default: peopleserver)"
	@echo "  DOMAIN_NAME    - Custom domain name (for deploy-domain)"
	@echo "  CERTIFICATE_ARN - ACM certificate ARN (for deploy-domain)"
