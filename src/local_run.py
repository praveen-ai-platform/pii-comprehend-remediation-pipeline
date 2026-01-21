from lambda_handler import lambda_handler

if __name__ == "__main__":
    demo = {
        "records": [
            {"message": "Payment failed for card 4111 1111 1111 1111. Contact user naga@example.com"},
            {"message": "Customer phone +919611345522 reported issue on checkout"},
            {"message": "No pii here - normal log line"}
        ]
    }
    res = lambda_handler(demo)
    print(res)
