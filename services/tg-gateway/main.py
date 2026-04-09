import os
import asyncio
import logging
from aiogram import Bot, Dispatcher, types
from aiogram.filters import CommandStart
import google.generativeai as genai

# Настройка логирования
logging.basicConfig(level=logging.INFO)

# Функция чтения секретов
def get_secret(name):
    try:
        # Пытаемся прочитать из Docker Secrets
        with open(f"/run/secrets/{name}", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        # Fallback на переменные окружения (для тестов)
        return os.getenv(name.upper().replace('.', '_'))

# Инициализация
TG_TOKEN = get_secret("tg_bot_token.txt")
GOOGLE_API_KEY = get_secret("google_api_key.txt")

if not TG_TOKEN or not GOOGLE_API_KEY:
    logging.error("Критическая ошибка: Ключи не найдены в /run/secrets/")
    exit(1)

genai.configure(api_key=GOOGLE_API_KEY)
# Используем 1.5-flash (она же 3.1 Flash в API Studio)
model = genai.GenerativeModel('gemini-3.1-flash-live-preview')

bot = Bot(token=TG_TOKEN)
dp = Dispatcher()

@dp.message(CommandStart())
async def cmd_start(message: types.Message):
    await message.answer("Шеф, Ворота Цитадели открыты. Я на связи через Gemini 3.1 Flash. Слушаю.")

@dp.message()
async def handle_message(message: types.Message):
    if not message.text:
        return
    
    await bot.send_chat_action(message.chat.id, "typing")
    
    try:
        response = await asyncio.to_thread(model.generate_content, message.text)
        await message.answer(response.text)
    except Exception as e:
        logging.error(f"Error: {e}")
        await message.answer("Ошибка связи с ядром Gemini. Проверь ключи.")

async def main():
    logging.info("Бот запускается...")
    await dp.start_polling(bot)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logging.info("Бот остановлен.")
