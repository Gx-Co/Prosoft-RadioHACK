from fastapi import FastAPI, Request, Depends, HTTPException, status, Form
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Базовая HTTP аутентификация
security = HTTPBasic()

# Данные пользователей (в реальном приложении хранить в БД)

USERS = {
    "admin": {
        "password": "admin123",
        "role": "admin",
        "password_changed": False
    },
    "user": {
        "password": "user123",
        "role": "user",
        "password_changed": True  # Для user пароль уже считается измененным
    }
}

DEFAULT_PASSWORDS = ["admin123", "user123"]  # Все пароли по умолчанию


def authenticate_user(credentials: HTTPBasicCredentials = Depends(security)):
    user = USERS.get(credentials.username)
    if not user or user["password"] != credentials.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверные учетные данные",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request):
    # Проверка авторизации
    username = request.cookies.get("user")
    if not username or username not in USERS:
        return RedirectResponse(url="/login")

    return templates.TemplateResponse("change_password.html", {"request": request})


@app.post("/login")
async def login(request: Request):
    form_data = await request.form()
    username = form_data.get("username")
    password = form_data.get("password")

    user = USERS.get(username)
    if not user or user["password"] != password:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Неверное имя пользователя или пароль"}
        )

    # Проверяем, используется ли пароль по умолчанию
    is_default_password = (password in DEFAULT_PASSWORDS and not user["password_changed"])

    response = RedirectResponse(
        url="/change-password" if is_default_password else "/",
        status_code=status.HTTP_302_FOUND
    )
    response.set_cookie(key="user", value=username)
    response.set_cookie(key="force_password_change", value=str(is_default_password).lower())
    return response


@app.post("/change-password")
async def change_password(
        request: Request,
        new_password: str = Form(...),
        confirm_password: str = Form(...)
):
    # Проверка авторизации
    username = request.cookies.get("user")
    if not username or username not in USERS:
        return RedirectResponse(url="/login")

    # Проверка совпадения новых паролей
    if new_password != confirm_password:
        return templates.TemplateResponse(
            "change_password.html",
            {"request": request, "error": "Пароли не совпадают"}
        )

    # Проверка длины пароля
    if len(new_password) < 8:
        return templates.TemplateResponse(
            "change_password.html",
            {"request": request, "error": "Пароль должен содержать не менее 8 символов"}
        )

    # Проверка, что новый пароль не совпадает с паролем по умолчанию
    if new_password in DEFAULT_PASSWORDS:
        return templates.TemplateResponse(
            "change_password.html",
            {"request": request, "error": "Новый пароль не должен совпадать с паролем по умолчанию"}
        )

    # Обновление пароля
    USERS[username]["password"] = new_password
    USERS[username]["password_changed"] = True

    # Перенаправление на главную страницу после успешной смены пароля
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.delete_cookie(key="force_password_change")
    return response


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    # Проверка авторизации через куки
    username = request.cookies.get("user")
    print(f"Dashboard access attempt by: {username}")

    if not username or username not in USERS:
        print("Redirecting to login - no valid user cookie")
        return RedirectResponse(url="/login")

    # Проверяем, требуется ли принудительная смена пароля
    force_password_change = request.cookies.get("force_password_change")
    print(f"Force password change: {force_password_change}")

    if force_password_change == "true":
        print("Redirecting to change password")
        return RedirectResponse(url="/change-password")

    return templates.TemplateResponse("index.html", {"request": request, "username": username})


@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/login")
    response.delete_cookie(key="user")
    response.delete_cookie(key="force_password_change")
    return response


# Защищенные API endpoints
@app.get("/api/protected")
async def protected_route(user: str = Depends(authenticate_user)):
    return {"message": f"Добро пожаловать, {user}!"}
