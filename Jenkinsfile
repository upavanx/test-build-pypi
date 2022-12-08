pipeline {

    agent {
         node {
            label 'aws-ec2'
         }
    }
    
    triggers {
        gitlab(triggerOnPush: true, branchFilterType: 'All')
    }

    
    options {
        gitLabConnection('Intel-Gitlab')
        gitlabCommitStatus(name: 'jenkins')
    }


    stages {
        stage('Setup') {
            steps {
                sh '''
                    while pgrep apt > /dev/null; do
                        sleep 10
                    done
                    sudo apt-get update 
                    sudo apt-get install -y python3 python3-pip
                    pip3 install setuptools
                '''
            }
        }
        stage('Build') {
            steps {
                sh '''
                    sudo python3 setup.py install
                    sudo pip3 install pyinstaller
                    sudo pip3 install defusedxml
                    sudo pyinstaller edgesoftware.spec
                '''
            }
        }
        stage('Validate') {
            steps {
                sh '''
                    python3 test/functional/test.py
                    python3 test/unit/test_utils.py 
                '''
            }
        }
    }
    
    post {
        success {
            emailext(
                body: '$DEFAULT_CONTENT',
                replyTo: '$DEFAULT_REPLYTO',
                subject: '$DEFAULT_SUBJECT',
                to: '$gitlabUserEmail',
            )
            updateGitlabCommitStatus name: 'build', state: 'success'
        }
        failure {
            emailext(
                body: '$DEFAULT_CONTENT',
                replyTo: '$DEFAULT_REPLYTO',
                subject: '$DEFAULT_SUBJECT',
                to: '$gitlabUserEmail',
            )
            updateGitlabCommitStatus name: 'build', state: 'failed'
        }
  }
}
