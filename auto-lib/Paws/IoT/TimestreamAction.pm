# Generated by default/object.tt
package Paws::IoT::TimestreamAction;
  use Moose;
  has DatabaseName => (is => 'ro', isa => 'Str', request_name => 'databaseName', traits => ['NameInRequest'], required => 1);
  has Dimensions => (is => 'ro', isa => 'ArrayRef[Paws::IoT::TimestreamDimension]', request_name => 'dimensions', traits => ['NameInRequest'], required => 1);
  has RoleArn => (is => 'ro', isa => 'Str', request_name => 'roleArn', traits => ['NameInRequest'], required => 1);
  has TableName => (is => 'ro', isa => 'Str', request_name => 'tableName', traits => ['NameInRequest'], required => 1);
  has Timestamp => (is => 'ro', isa => 'Paws::IoT::TimestreamTimestamp', request_name => 'timestamp', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::IoT::TimestreamAction

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::IoT::TimestreamAction object:

  $service_obj->Method(Att1 => { DatabaseName => $value, ..., Timestamp => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::IoT::TimestreamAction object:

  $result = $service_obj->Method(...);
  $result->Att1->DatabaseName

=head1 DESCRIPTION

The Timestream rule action writes attributes (measures) from an MQTT
message into an Amazon Timestream table. For more information, see the
Timestream
(https://docs.aws.amazon.com/iot/latest/developerguide/timestream-rule-action.html)
topic rule action documentation.

=head1 ATTRIBUTES


=head2 B<REQUIRED> DatabaseName => Str

The name of an Amazon Timestream database.


=head2 B<REQUIRED> Dimensions => ArrayRef[L<Paws::IoT::TimestreamDimension>]

Metadata attributes of the time series that are written in each measure
record.


=head2 B<REQUIRED> RoleArn => Str

The ARN of the role that grants permission to write to the Amazon
Timestream database table.


=head2 B<REQUIRED> TableName => Str

The name of the database table into which to write the measure records.


=head2 Timestamp => L<Paws::IoT::TimestreamTimestamp>

Specifies an application-defined value to replace the default value
assigned to the Timestream record's timestamp in the C<time> column.

You can use this property to specify the value and the precision of the
Timestream record's timestamp. You can specify a value from the message
payload or a value computed by a substitution template.

If omitted, the topic rule action assigns the timestamp, in
milliseconds, at the time it processed the rule.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::IoT>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

