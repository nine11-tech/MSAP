# Demo Scenario - MSAP

## Scenario
1. Deploy MSAP on Kubernetes/K3s using Helm.
2. Verify pods, services, Ingress, Redis, PostgreSQL and MinIO.
3. Create a project and audit.
4. Upload an authorized APK.
5. Show the APK object in MinIO bucket `msap-apk-uploads`.
6. Run worker analysis through Redis/Celery or Kubernetes Job.
7. Show artifacts and evidence objects in MinIO.
8. Review MASVS findings and ATT&CK Mobile triage indicators.
9. Generate a PDF report and JSON export.
10. Show report object in MinIO and download it through authorized API flow.

## Messaging
The demo must emphasize evidence-first static analysis, MASVS assessment, cautious ATT&CK Mobile triage and no guaranteed malware classification.
