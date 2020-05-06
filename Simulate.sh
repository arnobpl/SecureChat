vmoption="-Djava.util.logging.config.file=../logging.properties -classpath ../target/classes:/home/arnob/.m2/repository/org/xerial/sqlite-jdbc/3.30.1/sqlite-jdbc-3.30.1.jar:/home/arnob/.m2/repository/org/apache/commons/commons-lang3/3.10/commons-lang3-3.10.jar com.arnobpaul.Main"

cd data
gnome-terminal -- bash -c "echo 'Server'; java ${vmoption} -s"
sleep 0.5
gnome-terminal -- bash -c "echo 'Client C1'; java ${vmoption} -c C1"
gnome-terminal -- bash -c "echo 'Client C2'; java ${vmoption} -c C2"
gnome-terminal -- bash -c "echo 'Client C3'; java ${vmoption} -c C3"
gnome-terminal -- bash -c "echo 'Client C4'; java ${vmoption} -c C4"

