# GitLab CI/CD Baseline

## Repository roles

GitHub is the primary source repository and uses the `origin` remote. GitLab is
the secondary CI/CD repository and uses the `gitlab` remote. Normal development
should preserve GitHub as the source of record while pushing the same reviewed
commits to GitLab when a GitLab pipeline is required.

This baseline validates, tests, builds, and conditionally publishes production
container images. It does not deploy MSAP and does not perform Android dynamic
analysis.

## Pipeline creation

GitLab creates pipelines for:

- merge requests;
- the default branch;
- Git tags;
- ordinary branch pushes when the branch has no open merge request; and
- pipelines started manually from the GitLab web interface.

When a branch has an open merge request, the branch pipeline is suppressed in
favor of the merge-request pipeline. This avoids running the same commit twice.

## Stages and jobs

The configured stages are `validate`, `test`, `build`, `publish`, and `deploy`.
The `deploy` stage has no job and therefore remains absent from the visible
pipeline until a real environment and deployment method are configured.

The current jobs are:

| Stage | Job | Purpose |
|---|---|---|
| validate | `repository:validate` | Check whitespace, required files, prohibited tracked artifacts, and application version consistency |
| validate | `rules:validate` | Validate deterministic rules and detect missing Django migrations |
| validate | `compose:validate` | Parse and normalize Compose configuration without starting services |
| validate | `helm:validate` | Strictly lint and render default and local Helm values without contacting Kubernetes |
| test | `backend:test` | Run pytest with the Django testing settings and publish JUnit results |
| build | `frontend:build` | Install locked npm dependencies, apply the audit policy, build Vite, and retain `dist` temporarily |
| publish | `container:backend` | Build the production backend image and publish only on permitted refs |
| publish | `container:frontend` | Build the production frontend image and publish only on permitted refs |

Stage ordering ensures that container publication cannot start if validation,
backend tests, the dependency audit, or the frontend production build fails.

## Branch and merge-request behavior

An ordinary branch push runs all validation, test, frontend build, and
production container build-verification jobs. The images receive local
verification tags based on `CI_COMMIT_REF_SLUG` and the short commit SHA, but
they are not authenticated to or pushed into the registry.

A merge-request pipeline performs the same checks. It never publishes an image
and never deploys. Pipelines for untrusted forks must remain on unprivileged
shared runners; they must never be routed to the future Android runner.

## Default-branch behavior

A successful default-branch pipeline publishes:

- `$CI_REGISTRY_IMAGE/backend:main-$CI_COMMIT_SHORT_SHA`
- `$CI_REGISTRY_IMAGE/backend:latest`
- `$CI_REGISTRY_IMAGE/frontend:main-$CI_COMMIT_SHORT_SHA`
- `$CI_REGISTRY_IMAGE/frontend:latest`

The commit-qualified tags provide traceability. `latest` is updated only in a
default-branch container job after that image has built successfully. Registry
authentication uses the predefined `CI_REGISTRY_USER` and
`CI_REGISTRY_PASSWORD` variables through `docker login --password-stdin`.

## Tag behavior

Tag pipelines run the same validation, tests, frontend build, and production
image builds. They publish:

- `$CI_REGISTRY_IMAGE/backend:$CI_COMMIT_TAG`
- `$CI_REGISTRY_IMAGE/frontend:$CI_COMMIT_TAG`

Tag pipelines do not update `latest`. This avoids treating every tag as the
stable release. Release tags are intended to use semantic versions; production
deployment will later require protected semantic-version tags.

## Python and frontend dependency policy

Python jobs use Python 3.12 and install `backend/requirements.txt`. Pip downloads
are cached under `.cache/pip`; virtual environments are not cached. Backend
tests use `msap.settings.testing`, in-memory SQLite, eager Celery, and no
PostgreSQL, Redis, or MinIO CI services.

The frontend job uses the lockfile with `npm ci`, caches npm downloads under
`.cache/npm`, and does not cache `node_modules`. Its audit policy blocks all
critical findings and all high findings except one explicitly accepted
advisory:

- `GHSA-qwww-vcr4-c8h2`, React Router RSC-mode CSRF/action execution.

MSAP uses React Router as a client-rendered application and does not use the
unstable RSC APIs or server actions affected by that advisory. The locked
React Router 7 release has no compatible patched 7.x release; the published fix
requires React Router 8.3.0. The exception is narrow, visible in CI output, and
must be reviewed whenever frontend dependencies or routing architecture change.
The pipeline does not run `npm audit fix --force` and does not downgrade React
Router.

## Caches and artifacts

Only pip and npm download caches are retained. The pipeline does not cache
virtual environments, `node_modules`, credentials, APKs, generated reports,
object-storage data, or databases.

Short-lived artifacts are limited to:

- pytest JUnit XML, retained for seven days and uploaded even when tests fail;
- `frontend/dist`, retained for three days; and
- default/local rendered Helm YAML, retained for three days.

These generated paths remain untracked and must not be committed.

## Security boundaries

The pipeline contains no application password, private key, Django secret key,
MinIO credential, personal access token, GitHub token, kubeconfig, APK sample,
or application report. Registry pushes use only GitLab predefined job
credentials and never print the password.

Repository validation also rejects common high-confidence credential formats
and prints only file/line locations, never matched values. The local
`scripts/security/scan-secrets.sh --history` check additionally covers all
reachable commits before a release. Pattern scanning complements review and
credential rotation; it is not a proof that every custom secret format is
absent.

Jobs are interruptible except container jobs, which avoid interruption during a
registry publication. Docker-in-Docker is isolated to the two container jobs.
Those jobs require a runner capable of privileged Docker services; all other
jobs remain unprivileged. No pipeline job starts the Compose stack, contacts a
Kubernetes cluster, or executes an APK.

## Future deployment policy

No deployment target is currently defined, so no deployment job or script
exists. Once a real Docker Compose or Kubernetes target is approved:

- feature-branch and merge-request pipelines will never deploy;
- a successful default-branch pipeline will deploy automatically to the
  configured development or staging environment;
- production deployment will require a protected semantic-version tag, a
  protected production environment, and an approval/manual gate; and
- deployment must use immutable image tags from the successful pipeline.

Later deployment jobs are expected to require protected GitLab CI/CD variables
similar to:

- `MSAP_STAGING_KUBECONFIG` (protected file variable);
- `MSAP_STAGING_NAMESPACE` and `MSAP_STAGING_URL`;
- `MSAP_PRODUCTION_KUBECONFIG` (protected file variable);
- `MSAP_PRODUCTION_NAMESPACE` and `MSAP_PRODUCTION_URL`; and
- environment-specific Helm values as protected file variables when they
  cannot be sourced from a separately controlled configuration repository.

Secret application values should be supplied by the target platform's secret
manager, not embedded in Helm values or CI YAML. Mask secret variables wherever
GitLab supports their format. None of these deployment variables is required by
the current pipeline, and no deployment secrets should be added yet.

## Future Android dynamic runner

Dynamic Android analysis remains out of scope. Future emulator jobs will use a
dedicated, project-locked, protected runner tagged `android-dynamic`. The runner
must accept only protected refs and trusted project members. It must never run
untrusted fork pipelines, merge-request code from public contributors, or
arbitrary public project code. Emulator isolation, cleanup, APK retention, and
egress controls must be designed before any dynamic-analysis job is enabled.
