# Reporting

## Job scope reports (historical)

- Built from completed scan jobs and their snapshot history.
- Best for:
  - drift/trend analysis
  - historical comparisons
  - baseline-oriented review

## Inventory scope reports (current state)

- Built from current inventory (assets and current finding state).
- Best for:
  - current asset counts
  - current lifecycle status
  - open finding distribution now

## When to use each

- Use **Job scope** when you are answering "what did scans show over time?"
- Use **Inventory scope** when you are answering "what is true for this scope right now?"

## Common confusion scenarios

- A named scope contains assets but has no completed scoped jobs:
  - Job scope report can look empty.
  - Inventory scope report still shows current data.
- A historical job exists for a scope, but asset assignment later changed:
  - Job scope reflects historical run context.
  - Inventory scope reflects present assignment context.
