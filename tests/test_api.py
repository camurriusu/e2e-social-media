from http import HTTPStatus


def test_health(client):
    response = client.get("/api/health")

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == {"status": "ok"}


def test_create_and_fetch_user(client):
    create_response = client.post(
        "/api/users",
        json={"username": "John Doe"},
    )

    assert create_response.status_code == HTTPStatus.CREATED
    created_item = create_response.get_json()
    assert created_item["id"] == 1

    get_response = client.get("/api/users/1")
    assert get_response.status_code == HTTPStatus.OK
    fetched_item = get_response.get_json()
    assert fetched_item["username"] == "John Doe"


def test_create_item_validation(client):
    response = client.post("/api/users", json={"username": ""})

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "required" in response.get_json()["error"]

