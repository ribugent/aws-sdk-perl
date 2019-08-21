package Paws::DynamoDB::CreateGlobalSecondaryIndexAction;
  use Moo;
  use Types::Standard qw/Str ArrayRef/;
  use Paws::DynamoDB::TypeLibrary qw/PawsDynamoDBProjection PawsDynamoDBProvisionedThroughput PawsDynamoDBKeySchemaElement/;
  has IndexName => (is => 'ro', isa => Str, required => 1);
  has KeySchema => (is => 'ro', isa => ArrayRef[PawsDynamoDBKeySchemaElement], required => 1);
  has Projection => (is => 'ro', isa => PawsDynamoDBProjection, required => 1);
  has ProvisionedThroughput => (is => 'ro', isa => PawsDynamoDBProvisionedThroughput);

  sub params_map {
    my $params1 = {
             'types' => {
                          'IndexName' => {
                                           'type' => 'Str'
                                         },
                          'KeySchema' => {
                                           'class' => 'Paws::DynamoDB::KeySchemaElement',
                                           'type' => 'ArrayRef[PawsDynamoDBKeySchemaElement]'
                                         },
                          'Projection' => {
                                            'class' => 'Paws::DynamoDB::Projection',
                                            'type' => 'PawsDynamoDBProjection'
                                          },
                          'ProvisionedThroughput' => {
                                                       'class' => 'Paws::DynamoDB::ProvisionedThroughput',
                                                       'type' => 'PawsDynamoDBProvisionedThroughput'
                                                     }
                        }
           };

    return $params1;
  }

1;

### main pod documentation begin ###

=head1 NAME

Paws::DynamoDB::CreateGlobalSecondaryIndexAction

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::DynamoDB::CreateGlobalSecondaryIndexAction object:

  $service_obj->Method(Att1 => { IndexName => $value, ..., ProvisionedThroughput => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::DynamoDB::CreateGlobalSecondaryIndexAction object:

  $result = $service_obj->Method(...);
  $result->Att1->IndexName

=head1 DESCRIPTION

Represents a new global secondary index to be added to an existing
table.

=head1 ATTRIBUTES


=head2 B<REQUIRED> IndexName => Str

  The name of the global secondary index to be created.


=head2 B<REQUIRED> KeySchema => ArrayRef[PawsDynamoDBKeySchemaElement]

  The key schema for the global secondary index.


=head2 B<REQUIRED> Projection => PawsDynamoDBProjection

  Represents attributes that are copied (projected) from the table into
an index. These are in addition to the primary key attributes and index
key attributes, which are automatically projected.


=head2 ProvisionedThroughput => PawsDynamoDBProvisionedThroughput

  Represents the provisioned throughput settings for the specified global
secondary index.

For current minimum and maximum provisioned throughput values, see
Limits
(https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Limits.html)
in the I<Amazon DynamoDB Developer Guide>.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::DynamoDB>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

