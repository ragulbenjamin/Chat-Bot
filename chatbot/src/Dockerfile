# Use an official lightweight Python image
FROM python:3.11-slim

# Set the working directory inside the container
WORKDIR /code

# Copy requirements first to leverage Docker cache layers
COPY ./requirements.txt /code/requirements.txt

# Install the dependencies
RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

# Copy the rest of the application code
COPY . /code

# Expose the port FastAPI will run on
EXPOSE 8000

# Start Uvicorn, binding to 0.0.0.0 so external connections can reach it
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
