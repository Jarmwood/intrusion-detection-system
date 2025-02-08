# Use an official Python base image
FROM python:3.11-slim

# Set the working directory
WORKDIR /app

# Install dependencies: wget, curl, and bzip2 (for Conda)
RUN apt-get update && \
    apt-get install -y wget curl bzip2 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Install Miniconda (or Anaconda)
RUN wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh && \
    bash Miniconda3-latest-Linux-x86_64.sh -b -f -p /opt/conda && \
    rm Miniconda3-latest-Linux-x86_64.sh && \
    /opt/conda/bin/conda init

# Make conda available in the PATH
ENV PATH="/opt/conda/bin:$PATH"

# Copy your environment.yml file to the container
COPY env.yml /app/

# Create a non-privileged user that the app will run under.
# See https://docs.docker.com/go/dockerfile-user-best-practices/
ARG UID=10001
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    appuser

# Create the conda environment based on the environment file
RUN conda env create -f env.yml

# Activate the environment and set the default environment to be used
RUN echo "conda activate intrusionDetectionSystem" >> ~/.bashrc

# Set the entry point to activate the conda environment
ENTRYPOINT ["conda", "run", "--no-capture-output", "-n", "intrusionDetectionSystem"]


CMD ["python","main.py"]
