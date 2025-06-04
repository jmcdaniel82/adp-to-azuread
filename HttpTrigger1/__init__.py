import logging
import azure.functions as func

from function_app import process_request  # Import the processing function


def main(req: func.HttpRequest) -> func.HttpResponse:
    """Azure Function Trigger for ADP → Microsoft Entra Provisioning"""
    logging.info(
        "Azure Function Triggered for ADP → Microsoft Entra Provisioning"
    )
    try:
        # Simply call the process_request function which returns an HttpResponse
        return process_request(req)
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        return func.HttpResponse("Internal Server Error", status_code=500)
