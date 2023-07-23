pending_authorizations = []


def authorizes(gmail):
    """Adds the authorized email to the pending authorizations list."""
    pending_authorizations.append(gmail)


def oauth2callback():
    """Callback function for OAuth 2.0 authorization flow."""
    gmail = flask.session.get('gmail')
    if not gmail:
        return "Invalid request.", 400
    pending_authorizations.remove(gmail)
    return "Authorization completed successfully.", 200


def poll_server():
    """Polls the server every 30 seconds to check for authorized emails and process tokens."""
    while True:
        for email in pending_authorizations:
            # Retrieve the token for the email from the database
            collection_name = f'{email}_tokens'
            collection = db[collection_name]
            token = collection.find_one({'_id': 1})['token']

            if token:
                # Use the token to process and print free times
                print_free_times(token)

                # Delete the email from the pending authorizations list
                pending_authorizations.remove(email)

        # Pause for 30 seconds before the next poll
        time.sleep(30)


def print_free_times(token):
    """Prints the free times using the provided token."""
    credentials = google.oauth2.credentials.Credentials.from_authorized_user_info(token, SCOPES)
    service = googleapiclient.discovery.build(API_SERVICE_NAME, API_VERSION, credentials=credentials)

    # Call the Calendar API to retrieve the events.
    events_result = service.events().list(calendarId='primary', timeMin='2023-05-28T12:00:00Z',
                                          timeMax='2023-05-28T23:59:59Z', singleEvents=True).execute()
    events = events_result.get('items', [])

    # Save credentials back to session in case access token was refreshed.
    flask.session['credentials'] = credentials_to_dict(credentials)

    # Calculate free times
    free_times = get_free_times(events)

    # Generate free times if no events are found
    if not free_times:
        free_times = generate_free_times(datetime.datetime(2023, 6, 14), datetime.datetime(2023, 6, 14, 23, 59, 59), 3)

    # Prepare the free time data to be returned
    free_times_list = []
    for i, free_time in enumerate(free_times, start=1):
        free_time_data = {
            'id': i,
            'start_time': str(free_time[0]),
            'end_time': str(free_time[1])
        }
        free_times_list.append(free_time_data)

    print(free_times_list)