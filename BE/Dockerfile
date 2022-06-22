FROM openjdk:11-jdk

COPY ./BE/build/libs/*.jar issuetracker.jar

ENTRYPOINT ["java", "-jar", "-Dspring.profiles.active=prod", "-Dcom.amazonaws.sdk.disableEc2Metadata=true", "issuetracker.jar"]
