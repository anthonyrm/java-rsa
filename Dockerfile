FROM openjdk:8-alpine
COPY target/*security*.jar app.jar
COPY rsa/ rsa/
EXPOSE 8080
CMD ["java", "-jar", "app.jar"]