FROM python:3.12-alpine as build

WORKDIR /app

COPY pod-external-dns.py /app
COPY requirements.txt /app

RUN apk add binutils
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir pyinstaller

RUN pyinstaller --onefile pod-external-dns.py

##############################################################

FROM alpine
COPY --from=build /app/dist/pod-external-dns /pod-external-dns

CMD [ "/daemon"]
