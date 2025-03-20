with app.app_context():
    db.create_all()
    # Add sample questions if table is empty
    if not Question.query.first():
        sample_questions = [
            Question(
                exam_type='aws_cloud_practitioner',
                question_text='What is the primary use of AWS S3?',
                option_a='Compute', option_b='Storage', option_c='Networking', option_d='Database',
                correct_answer='Storage'
            ),
            Question(
                exam_type='aws_cloud_practitioner',
                question_text='Which AWS service is used for virtual servers?',
                option_a='S3', option_b='EC2', option_c='RDS', option_d='Lambda',
                correct_answer='EC2'
            ),
            Question(
                exam_type='azure_fundamentals',
                question_text='What is Azure Blob Storage used for?',
                option_a='Virtual Machines', option_b='Unstructured Data', option_c='SQL Databases', option_d='Networking',
                correct_answer='Unstructured Data'
            )
        ]
        db.session.bulk_save_objects(sample_questions)
        db.session.commit()