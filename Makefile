PROJECT_ID=$(shell gcloud config get-value project)

service-account.json:
	gcloud iam service-accounts keys create --iam-account=dlp-agent@${PROJECT_ID}.iam.gserviceaccount.com service-account.json

env:
	@echo export GOOGLE_APPLICATION_CREDENTIALS=$(shell pwd)/service-account.json
	@echo export PROJECT_ID=${PROJECT_ID}

.PHONY: service-account
service-account:
	gcloud iam service-accounts create dlp-agent --display-name "Service Account for DLP cli tools"

.PHONY: service-account-permissions
service-account-permissions:
	gcloud projects add-iam-policy-binding ${PROJECT_ID} \
	  --member serviceAccount:dlp-agent@${PROJECT_ID}.iam.gserviceaccount.com \
	  --role roles/dlp.user
