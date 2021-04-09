FROM python
LABEL maintainer="davydkin.dmitry@gmail.com"
WORKDIR /home/
RUN git clone https://github.com/Aelean99/HikvisionAutoConfig.git
WORKDIR /home/HikvisionAutoConfig
COPY passwords.json /home/HikvisionAutoConfig
RUN pip install -r requirements.txt
EXPOSE 3050
CMD ["gunicorn", "-w 5", "-b 0.0.0.0", "hikvision:app", "-k uvicorn.workers.UvicornWorker"]

