# GCP Deployment Guide

This guide deploys `fyp2 - The Digital Footprint` to Google Cloud Platform using a simple FYP-friendly architecture:

```text
User Browser
  -> Compute Engine VM public IP:8501
  -> Streamlit dashboard container
  -> Flask API container
  -> Celery worker container
  -> Redis container
  -> Cloud SQL Auth Proxy container
  -> Cloud SQL for PostgreSQL
```

This is the recommended route for your FYP because it demonstrates cloud hosting, containerization, managed database usage, background processing, and secret handling without making the deployment as complex as Kubernetes.

## 1. What You Need

Install these on your laptop:

- Google Cloud account with billing enabled
- Google Cloud CLI
- Git or a ZIP copy of this project
- Optional: Docker Desktop, only if you want to build locally first

Recommended GCP region for Malaysia:

```text
asia-southeast1
```

Recommended VM size for demo:

```text
e2-medium
```

For a very small demo, `e2-small` may work, but Celery, Streamlit, Flask, Redis, and the Cloud SQL Proxy are more comfortable on `e2-medium`.

## 2. Set Project Variables

Run these from your local terminal after logging in with `gcloud init`.

```powershell
$env:PROJECT_ID="your-gcp-project-id"
$env:REGION="asia-southeast1"
$env:ZONE="asia-southeast1-b"
$env:VM_NAME="fyp2-vm"
$env:SQL_INSTANCE="fyp2-postgres"

gcloud config set project $env:PROJECT_ID
```

Enable the required services:

```powershell
gcloud services enable compute.googleapis.com
gcloud services enable sqladmin.googleapis.com
gcloud services enable secretmanager.googleapis.com
gcloud services enable artifactregistry.googleapis.com
```

## 3. Create Cloud SQL for PostgreSQL

For a low-cost FYP demo, use a small PostgreSQL instance:

```powershell
gcloud sql instances create $env:SQL_INSTANCE `
  --database-version=POSTGRES_15 `
  --tier=db-f1-micro `
  --region=$env:REGION `
  --storage-size=10GB
```

Create the application database:

```powershell
gcloud sql databases create fyp2 --instance=$env:SQL_INSTANCE
```

Create the database user:

```powershell
$env:DB_PASSWORD="replace-with-a-strong-password"

gcloud sql users create fyp2 `
  --instance=$env:SQL_INSTANCE `
  --password=$env:DB_PASSWORD
```

Get the Cloud SQL connection name:

```powershell
gcloud sql instances describe $env:SQL_INSTANCE --format="value(connectionName)"
```

It will look like this:

```text
your-project-id:asia-southeast1:fyp2-postgres
```

Save it. You will use it in `.env`.

## 4. Create a VM Service Account

Create a service account for the VM:

```powershell
gcloud iam service-accounts create fyp2-vm-sa `
  --display-name="fyp2 VM service account"
```

Grant the VM permission to connect to Cloud SQL and read secrets:

```powershell
$env:VM_SA="fyp2-vm-sa@$env:PROJECT_ID.iam.gserviceaccount.com"

gcloud projects add-iam-policy-binding $env:PROJECT_ID `
  --member="serviceAccount:$env:VM_SA" `
  --role="roles/cloudsql.client"

gcloud projects add-iam-policy-binding $env:PROJECT_ID `
  --member="serviceAccount:$env:VM_SA" `
  --role="roles/secretmanager.secretAccessor"

gcloud projects add-iam-policy-binding $env:PROJECT_ID `
  --member="serviceAccount:$env:VM_SA" `
  --role="roles/logging.logWriter"
```

## 5. Create the Compute Engine VM

Create the VM:

```powershell
gcloud compute instances create $env:VM_NAME `
  --zone=$env:ZONE `
  --machine-type=e2-medium `
  --image-family=debian-12 `
  --image-project=debian-cloud `
  --boot-disk-size=30GB `
  --tags=fyp2-web `
  --service-account=$env:VM_SA `
  --scopes=cloud-platform
```

Create a firewall rule for the Streamlit dashboard:

```powershell
$env:MY_IP="YOUR_PUBLIC_IP/32"

gcloud compute firewall-rules create allow-fyp2-dashboard `
  --allow=tcp:8501 `
  --source-ranges=$env:MY_IP `
  --target-tags=fyp2-web `
  --description="Allow access to fyp2 Streamlit dashboard"
```

For a classroom demo where the marker needs access, you can temporarily use:

```powershell
--source-ranges=0.0.0.0/0
```

Use this only for demo convenience, then restrict or delete the rule after marking.

## 6. Connect to the VM

```powershell
gcloud compute ssh $env:VM_NAME --zone=$env:ZONE
```

Inside the VM, install Docker and supporting tools:

```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-plugin git
sudo usermod -aG docker $USER
```

Log out and SSH back in so the Docker group permission takes effect:

```bash
exit
```

Then reconnect:

```powershell
gcloud compute ssh $env:VM_NAME --zone=$env:ZONE
```

Check Docker:

```bash
docker --version
docker compose version
```

## 7. Upload or Clone the Project

Option A: Upload from your laptop.

From the parent folder that contains `fyp2`, run:

```powershell
gcloud compute scp --recurse fyp2 $env:VM_NAME:~/fyp2 --zone=$env:ZONE
```

Option B: Clone from GitHub if you pushed the project to a repository:

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git fyp2
```

Then enter the project:

```bash
cd ~/fyp2
```

## 8. Create the Production Environment File

Copy the GCP template:

```bash
cp .env.gcp.example .env
```

Edit it:

```bash
nano .env
```

Update these values:

```text
SECRET_KEY=replace-with-a-long-random-secret
DATABASE_URL=postgresql+psycopg2://fyp2:YOUR_DB_PASSWORD@cloud-sql-proxy:5432/fyp2
CLOUD_SQL_INSTANCE_CONNECTION_NAME=your-project-id:asia-southeast1:fyp2-postgres
```

Optional API keys:

```text
SHODAN_API_KEY=
GEMINI_API_KEY=
OPENAI_API_KEY=
```

Keep `.env` private. Do not upload it to GitHub.

## 9. Start the System

Run:

```bash
docker compose -f docker-compose.gcp.yml up -d --build
```

Check containers:

```bash
docker compose -f docker-compose.gcp.yml ps
```

Check logs:

```bash
docker compose -f docker-compose.gcp.yml logs -f api
docker compose -f docker-compose.gcp.yml logs -f dashboard
docker compose -f docker-compose.gcp.yml logs -f worker
```

The Flask API creates the required database tables automatically when it starts.

## 10. Open the System

Get the VM external IP:

```powershell
gcloud compute instances describe $env:VM_NAME `
  --zone=$env:ZONE `
  --format="value(networkInterfaces[0].accessConfigs[0].natIP)"
```

Open:

```text
http://VM_EXTERNAL_IP:8501
```

The API is intentionally bound to localhost on the VM in `docker-compose.gcp.yml`:

```text
127.0.0.1:5000:5000
```

That means users access the Streamlit dashboard, while the dashboard talks to the Flask API through Docker networking.

## 11. Optional: Use Secret Manager for API Keys

Create a secret:

```powershell
gcloud secrets create fyp2-openai-api-key --replication-policy=automatic
```

Add a value:

```powershell
"YOUR_API_KEY" | gcloud secrets versions add fyp2-openai-api-key --data-file=-
```

On the VM, read the secret:

```bash
gcloud secrets versions access latest --secret=fyp2-openai-api-key
```

For the FYP demo, you can manually paste the secret value into `.env`. For a more professional version, create a startup script that writes secrets into `.env` during deployment.

## 12. Updating the App

After changing code locally, upload again:

```powershell
gcloud compute scp --recurse fyp2 $env:VM_NAME:~/fyp2 --zone=$env:ZONE
```

Then on the VM:

```bash
cd ~/fyp2
docker compose -f docker-compose.gcp.yml up -d --build
```

## 13. Troubleshooting

### Dashboard does not open

Check the firewall source range:

```powershell
gcloud compute firewall-rules describe allow-fyp2-dashboard
```

Check if Streamlit is running:

```bash
docker compose -f docker-compose.gcp.yml logs dashboard
```

### Database connection fails

Check the Cloud SQL connection name in `.env`:

```bash
cat .env | grep CLOUD_SQL_INSTANCE_CONNECTION_NAME
```

Check the proxy logs:

```bash
docker compose -f docker-compose.gcp.yml logs cloud-sql-proxy
```

Confirm the VM service account has `roles/cloudsql.client`.

### Worker is not processing scans

Check Redis and worker:

```bash
docker compose -f docker-compose.gcp.yml logs redis
docker compose -f docker-compose.gcp.yml logs worker
```

Confirm this exists in `.env`:

```text
USE_CELERY=true
```

### API works but dashboard says local mode

Inside the dashboard container, the API URL should be:

```text
STREAMLIT_API_URL=http://api:5000
```

Do not set it to the public VM IP inside Docker.

## 14. Cleanup After Demo

Stop containers:

```bash
docker compose -f docker-compose.gcp.yml down
```

Delete the VM:

```powershell
gcloud compute instances delete $env:VM_NAME --zone=$env:ZONE
```

Delete Cloud SQL:

```powershell
gcloud sql instances delete $env:SQL_INSTANCE
```

Delete the firewall rule:

```powershell
gcloud compute firewall-rules delete allow-fyp2-dashboard
```

Cloud SQL can keep charging while running, so stop or delete it when you are done.

## 15. How to Explain This in Your FYP

You can describe the deployment like this:

```text
The system was deployed on Google Cloud Platform using a Compute Engine VM to host Dockerized application services. PostgreSQL was deployed as a managed Cloud SQL instance, while Redis was deployed as a containerized broker for Celery background tasks. The Flask API handles scan requests, Celery performs asynchronous scanning, Streamlit provides the web dashboard, and the Cloud SQL Auth Proxy provides secure database connectivity from the VM to Cloud SQL.
```

This gives you strong technical coverage for:

- Cloud infrastructure
- Docker containerization
- Managed relational database
- Background task processing
- API-based architecture
- Secure secret and database connection planning

## Official References

- Google Cloud CLI install: https://docs.cloud.google.com/sdk/docs/install
- Compute Engine instance creation command: https://cloud.google.com/sdk/gcloud/reference/compute/instances/create
- Compute Engine firewall rule command: https://cloud.google.com/sdk/gcloud/reference/compute/firewall-rules/create
- Cloud SQL PostgreSQL instance creation: https://cloud.google.com/sql/docs/postgres/create-instance
- Cloud SQL Auth Proxy: https://cloud.google.com/sql/docs/postgres/connect-auth-proxy
- Secret Manager quickstart: https://cloud.google.com/secret-manager/docs/create-secret-quickstart
- Artifact Registry Docker images: https://docs.cloud.google.com/artifact-registry/docs/docker

