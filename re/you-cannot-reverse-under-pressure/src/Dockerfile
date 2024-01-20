FROM alpine

RUN apk add go

RUN adduser --system challenge

RUN mkdir -p /app
RUN chown challenge /app

USER challenge
WORKDIR /app

COPY . .

RUN go build -o server .

RUN ./server -download

EXPOSE 8080

ENV FLAG "oiccflag{well_done_it_turns_out_you_can_do_this_pretty_fast}"

ENTRYPOINT [ "./server", "-address", ":8080" ]