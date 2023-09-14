package com.example.openapigateway;

import com.example.openApiClientSdk.utils.signUtils;
import lombok.extern.slf4j.Slf4j;
import model.entity.InterfaceInfo;
import model.entity.User;
import org.apache.dubbo.config.annotation.DubboReference;
import org.reactivestreams.Publisher;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import service.InnerUserService;
import service.innerInterfaceInfoService;
import service.innerUserInterfaceInfoService;

import java.nio.charset.StandardCharsets;
import java.util.*;

@Slf4j
@Component
public class CustomGlobalFilter implements GlobalFilter, Ordered {
    @DubboReference
    private InnerUserService innerUserService;

    @DubboReference
    private innerUserInterfaceInfoService innerUserInterfaceInfoService;

    @DubboReference
    private innerInterfaceInfoService innerInterfaceInfoService;

    private static final String HOST = "http://localhost:8001";

    private static final List<String> IP_WHITE_LIST = Arrays.asList("127.0.0.1");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        //请求日志
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().toString();
        String method = Objects.requireNonNull(request.getMethod()).toString();
        log.info("请求标识 " + request.getId());
        log.info("请求路径 " + path);
        log.info("请求方法 " + method);
        log.info("请求参数 " + request.getQueryParams());
        String address = request.getLocalAddress().getHostString();
        log.info("请求来源" + address);

        ServerHttpResponse response = exchange.getResponse();

        if (!IP_WHITE_LIST.contains(address)) {
            response.setStatusCode(HttpStatus.FORBIDDEN);
            return response.setComplete();
        }

        HttpHeaders headers = request.getHeaders();

        String accessKey = headers.getFirst("accessKey");
        String nonce = headers.getFirst("nonce");
        String timeStamp = headers.getFirst("timeStamp");
        String sign = headers.getFirst("sign");
        String body = headers.getFirst("body");

        User user = new User();
        try {
            user = innerUserService.getInvokeUser(accessKey, "null");
        } catch (Exception e) {
            log.error("getInvokeUser error");
        }
        if (user == null) {
            return handleNoAuth(response);
        }

        //todo 存随机数 map或者redis
        if (Long.parseLong(nonce) > 10000) {
            return handleNoAuth(response);
        }
        long currentTime = System.currentTimeMillis() / 1000;
        final long FIVE_MINUTES = 60 * 5L;
        if ((currentTime - Long.parseLong(timeStamp) >= FIVE_MINUTES)) {
            return handleNoAuth(response);
        }

        String secretKey = user.getSecretKey();

        HashMap<String, String> headerMap = new HashMap<>();
        headerMap.put("accessKey", accessKey);
        headerMap.put("nonce", nonce);
        headerMap.put("timeStamp", timeStamp);
        headerMap.put("body", body);
        String signRes = signUtils.getSign(headerMap, secretKey);
        //这里的secretKeys实际是数据库查出来的
        if (sign == null || !sign.equals(signRes)) {
            return handleNoAuth(response);
        }
        //      Mono<Void> filter = chain.filter(exchange);

        // 验证接口是否存在
        InterfaceInfo interfaceInfo = innerInterfaceInfoService.getInterfaceInfo(path, method);
        if (interfaceInfo == null) {
            return handleNoAuth(response);
        }


        return handleResponse(exchange, chain,interfaceInfo.getId(),interfaceInfo.getUserId());

//        if (response.getStatusCode() == HttpStatus.OK) {
//
//        } else {
//            return handleInvokeError(response);
//        }
//
//        return filter;
    }

    public Mono<Void> handleResponse(ServerWebExchange exchange, GatewayFilterChain chain,long interfaceInfoId,long userId) {
        try {
            ServerHttpResponse originalResponse = exchange.getResponse();
            // 缓存数据的工厂
            DataBufferFactory bufferFactory = originalResponse.bufferFactory();
            // 拿到响应码
            HttpStatus statusCode = originalResponse.getStatusCode();
            if (statusCode == HttpStatus.OK) {
                // 装饰，增强能力
                ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(originalResponse) {
                    // 等调用完转发的接口后才会执行
                    @Override
                    public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                        log.info("body instanceof Flux: {}", (body instanceof Flux));
                        if (body instanceof Flux) {
                            Flux<? extends DataBuffer> fluxBody = Flux.from(body);
                            // 往返回值里写数据
                            // 拼接字符串
                            return super.writeWith(
                                    fluxBody.map(dataBuffer -> {
                                        // 7. todo 调用成功，接口调用次数 + 1 invokeCount
                                        try {
                                            boolean b = innerUserInterfaceInfoService.invokeCount(interfaceInfoId,userId);
                                        } catch (Exception e){
                                            e.printStackTrace();
                                        }
                                        byte[] content = new byte[dataBuffer.readableByteCount()];
                                        dataBuffer.read(content);
                                        DataBufferUtils.release(dataBuffer);//释放掉内存
                                        // 构建日志
                                        StringBuilder sb2 = new StringBuilder(200);
                                        List<Object> rspArgs = new ArrayList<>();
                                        rspArgs.add(originalResponse.getStatusCode());
                                        String data = new String(content, StandardCharsets.UTF_8); //data
                                        sb2.append(data);
                                        // 打印日志
                                        log.info("响应结果：" + data);
                                        return bufferFactory.wrap(content);
                                    }));
                        } else {
                            // 8. 调用失败，返回一个规范的错误码
                            log.error("<--- {} 响应code异常", getStatusCode());
                        }
                        return super.writeWith(body);
                    }
                };
                // 设置 response 对象为装饰过的
                return chain.filter(exchange.mutate().response(decoratedResponse).build());
            }
            return chain.filter(exchange); // 降级处理返回数据
        } catch (Exception e) {
            log.error("网关处理响应异常" + e);
            return chain.filter(exchange);
        }
    }


    @Override
    public int getOrder() {
        return 0;
    }

    Mono<Void> handleNoAuth(ServerHttpResponse response) {
        response.setStatusCode(HttpStatus.FORBIDDEN);
        return response.setComplete();
    }

    Mono<Void> handleInvokeError(ServerHttpResponse response) {
        response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
        return response.setComplete();
    }
}
