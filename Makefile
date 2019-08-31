PROJECT_ID=$(shell gcloud config get-value project)

service-account.json:
	gcloud iam service-accounts keys create --iam-account=dlp-agent@${PROJECT_ID}.iam.gserviceaccount.com service-account.json

env:
	@echo export GOOGLE_APPLICATION_CREDENTIALS=$(shell pwd)/service-account.json

.PHONY: service-account
service-account:
	gcloud iam service-accounts create dlp-agent --display-name "Service Account for DLP cli tools"

