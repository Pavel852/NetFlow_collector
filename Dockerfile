# Use an official Ubuntu image as the base
FROM ubuntu:latest

# Install required packages
RUN apt-get update && \
    apt-get install -y \
    g++ \
    make \
    libsqlite3-dev \
    libmysqlclient-dev

# Set the working directory
WORKDIR /app

# Copy the source code to the container
COPY . .

# Build the project
RUN make

# Define the entry point to run the compiled executable
CMD ["./netflow_collector"]

