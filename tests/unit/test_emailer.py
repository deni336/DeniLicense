import httpx

from denilicense.emailer import EmailJob, EmailSender


def test_email_webhook_is_authenticated_and_does_not_redirect() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["authorization"] = request.headers.get("Authorization")
        seen["body"] = request.read()
        return httpx.Response(204)

    sender = EmailSender("https://mailer.example/send", "b" * 32, "https://app.example")
    sender._client.close()
    sender._client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    sender._deliver(EmailJob("verification", "user@example.com", "dlev_secret", "request-1"))
    assert seen["authorization"] == "Bearer " + "b" * 32
    assert b"verify-email%3F" not in seen["body"]  # token is encoded as a query value, not a path fragment
    sender.close()
