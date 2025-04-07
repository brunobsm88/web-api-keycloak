# MySecureApi

## Getting Started

### Prerequisites

- Docker
- Docker Compose

### Installation

1. Clone this repository:

https://github.com/brunobsm88/web-api-keycloak.git

2. Run the Docker Compose:
docker-compose up


3. Access the Keycloak UI at [http://localhost:8888/](http://localhost:8888/)
    ![Keycloak UI](https://github.com/user-attachments/assets/c0b51ec6-c956-4cb6-aae9-3a23138a2ff7)

### Keycloak Configuration

For detailed instructions on configuring Keycloak, refer to this article: [MEDIUM .NET Web API with Keycloak](https://medium.com/@faulycoelho/net-web-api-with-keycloak-11e0286240b9)

### Usage

#### Call API without Token

Try calling the API without a token:

curl --location 'https://localhost:7282/api/Values/get-admin'

You should receive an unauthorized response.

#### Generate a Token

Generate a new token by calling the Auth endpoint:

curl --location 'https://localhost:7282/api/Auth/login' 
--header 'Content-Type: application/json' 
--data '{ "username": "user-admin", "password": "123" }'

#### Call API with Token

Use the generated token to call the ValuesController:

curl --location 'https://localhost:7282/api/Values/get-admin' 
--header 'Authorization: Bearer <your-token-here>'

You should receive an HTTP 200 response:

