import datetime

def get_server_time():
  """Gets the current server time."""
  return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

if __name__ == "__main__":
  print(f"Magnum Core Pulse: OK {get_server_time()}")
