# Notifications setup (Section 10.1)

## Slack-compatible webhook (four steps)

1. Create an Incoming Webhook in your Slack workspace (or use any Slack-compatible endpoint).
2. Add the webhook URL to `notifications.outbound_webhooks` in the control-plane config (or inject via `${SLACK_WEBHOOK_URL}`).
3. Optionally filter events with `events: [approval_requested, case_resolved, …]`.
4. Restart `temporal-worker` (or roll the Deployment) so the new config is loaded.

Generic HTTPS webhooks use the same list with a plain URL and JSON body.

Events emitted: `approval_requested`, `case_resolved`, `case_rejected`, and related lifecycle notifications (see Section 10.1).
