.PHONY: build docker build-local run clean

# 本地构建
build-local:
	go build -o mdns-proxy .

# Docker构建
docker:
	docker build -t mdns-proxy .

# 本地运行
run:
	sudo ./mdns-proxy -src-iface eth0 -dst-iface wlan0 -verbose

# Docker运行
run-docker:
	docker run --rm \
		--name mdns-proxy \
		--network host \
		--cap-add NET_ADMIN \
		--cap-add NET_RAW \
		mdns-proxy -src-iface eth0 -dst-iface wlan0 -verbose

# 清理
clean:
	rm -f mdns-proxy
	docker rmi mdns-proxy || true
