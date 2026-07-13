# Project Setup Guide - MSAP Cloud

## Development purpose
This guide is for developer setup only. The target deployment platform is Kubernetes with Helm.

## Expected developer tools
Python, Node.js, Docker, Docker Compose for development, kubectl, Helm, kind or K3s, and access to MinIO/PostgreSQL/Redis development services.

## Development workflow
Use Docker Compose only to run local development dependencies quickly. Validate deployment behavior on kind/K3s with Helm before delivery.

## Cloud-native alignment
Development code should assume PostgreSQL metadata, MinIO object storage, Redis/Celery asynchronous workers, Kubernetes Secrets in target environments and object references instead of local filesystem paths.
