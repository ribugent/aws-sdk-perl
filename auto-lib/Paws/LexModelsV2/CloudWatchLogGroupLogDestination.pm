# Generated by default/object.tt
package Paws::LexModelsV2::CloudWatchLogGroupLogDestination;
  use Moose;
  has CloudWatchLogGroupArn => (is => 'ro', isa => 'Str', request_name => 'cloudWatchLogGroupArn', traits => ['NameInRequest'], required => 1);
  has LogPrefix => (is => 'ro', isa => 'Str', request_name => 'logPrefix', traits => ['NameInRequest'], required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::LexModelsV2::CloudWatchLogGroupLogDestination

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::LexModelsV2::CloudWatchLogGroupLogDestination object:

  $service_obj->Method(Att1 => { CloudWatchLogGroupArn => $value, ..., LogPrefix => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::LexModelsV2::CloudWatchLogGroupLogDestination object:

  $result = $service_obj->Method(...);
  $result->Att1->CloudWatchLogGroupArn

=head1 DESCRIPTION

The Amazon CloudWatch Logs log group where the text and metadata logs
are delivered. The log group must exist before you enable logging.

=head1 ATTRIBUTES


=head2 B<REQUIRED> CloudWatchLogGroupArn => Str

The Amazon Resource Name (ARN) of the log group where text and metadata
logs are delivered.


=head2 B<REQUIRED> LogPrefix => Str

The prefix of the log stream name within the log group that you
specified



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::LexModelsV2>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

