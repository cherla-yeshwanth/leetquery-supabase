# LeetQuery Supabase Backend

This repository contains the Supabase backend for LeetQuery.

## Structure

- `supabase/functions/make-server-19914029` - Edge Function source
- `.github/workflows/deploy-supabase.yml` - Auto-deploy workflow

## Local deploy command

```bash
supabase functions deploy make-server-19914029 --project-ref vwrlropkucvxqywopxwk
```

## Required GitHub Secrets

Set these in **Repo -> Settings -> Secrets and variables -> Actions**:

- `SUPABASE_ACCESS_TOKEN`
- `SUPABASE_PROJECT_REF` (value: `vwrlropkucvxqywopxwk`)
- `RESET_SECRET` (recommended)

## Auto-deploy

- Push to `main` with changes under `supabase/**`
- Or run manually from GitHub Actions (`workflow_dispatch`)
